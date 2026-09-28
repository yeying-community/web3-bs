export type CredentialStatusResponse = {
    issuer: string
    checkedAt: string
    nextUpdateAt: string
    statuses: Record<string, 'active' | 'revoked' | 'superseded' | 'expired' | 'unknown'>
}

export type IdentityCredentialValidation = {
    issuer: string
    subject: string
    credentialType: IdentityCredentialType
    credentialId: string
    payload: Record<string, unknown>
}

type IdentityCredentialType = 'EmailCredential' | 'UsernameCredential' | 'AvatarCredential' | 'WalletAccountCredential'

function decodePart(value: string) {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
    const bytes = Uint8Array.from(atob(`${normalized}${'='.repeat((4 - (normalized.length % 4)) % 4)}`), (char) =>
        char.charCodeAt(0)
    )
    return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
}

function decodeBase64Url(value: string) {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
    return Uint8Array.from(atob(`${normalized}${'='.repeat((4 - (normalized.length % 4)) % 4)}`), (char) =>
        char.charCodeAt(0)
    )
}

export function decodeIdentityCredential(token: string) {
    const parts = String(token || '').split('.')
    if (parts.length !== 3) throw new Error('IDENTITY_CREDENTIAL_INVALID')
    const header = decodePart(parts[0])
    const payload = decodePart(parts[1])
    if (header.alg !== 'EdDSA' || header.typ !== 'JWT' || typeof header.kid !== 'string')
        throw new Error('IDENTITY_CREDENTIAL_INVALID')
    return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: parts[2] }
}

export async function verifyIdentityCredential(
    token: string,
    options: {
        issuer: string
        publicJwk: JsonWebKey
        expectedSubject?: string
        expectedType: IdentityCredentialType
        now?: number
    }
) {
    const decoded = decodeIdentityCredential(token)
    const payload = decoded.payload
    if (payload.iss !== options.issuer || (options.expectedSubject && payload.sub !== options.expectedSubject))
        throw new Error('IDENTITY_ISSUER_UNTRUSTED')
    const vc = payload.vc as Record<string, unknown> | undefined
    const types = Array.isArray(vc?.type) ? vc.type : []
    if (!types.includes('VerifiableCredential') || !types.includes(options.expectedType))
        throw new Error('IDENTITY_CREDENTIAL_INVALID')
    const now = options.now || Math.floor(Date.now() / 1000)
    if (typeof payload.exp !== 'number' || typeof payload.nbf !== 'number' || payload.nbf > now || payload.exp <= now)
        throw new Error('IDENTITY_CREDENTIAL_EXPIRED')
    let valid = false
    try {
        const key = await globalThis.crypto.subtle.importKey('jwk', options.publicJwk, { name: 'Ed25519' }, false, [
            'verify'
        ])
        valid = await globalThis.crypto.subtle.verify(
            { name: 'Ed25519' },
            key,
            decodeBase64Url(decoded.signature),
            new TextEncoder().encode(decoded.signingInput)
        )
    } catch {
        valid = false
    }
    if (!valid) throw new Error('IDENTITY_CREDENTIAL_INVALID')
    return {
        issuer: String(payload.iss),
        subject: String(payload.sub),
        credentialType: options.expectedType,
        credentialId: String(payload.jti || ''),
        payload
    }
}

export async function queryCredentialStatuses(
    nodeBaseUrl: string,
    issuer: string,
    credentials: string[],
    fetcher: typeof fetch = fetch
): Promise<CredentialStatusResponse> {
    if (!issuer || credentials.length === 0) throw new Error('IDENTITY_CREDENTIAL_STATUS_REQUEST_INVALID')
    const response = await fetcher(`${nodeBaseUrl.replace(/\/$/, '')}/api/v1/public/identity/credentials/status`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ issuer, credentials })
    })
    if (!response.ok) throw new Error('IDENTITY_CREDENTIAL_STATUS_UNKNOWN')
    const envelope = (await response.json()) as { code: number; data?: CredentialStatusResponse }
    if (envelope.code !== 0 || !envelope.data) throw new Error('IDENTITY_CREDENTIAL_STATUS_UNKNOWN')
    return envelope.data
}
import { requestAccounts, requireProvider } from './provider'
import { setAccessToken } from './token'
import type {
    Eip1193Provider,
    IdentityPresentation,
    IdentityPresentationRequest,
    IdentityPresentationScope,
    IdentityPresentationValidationOptions,
    IdentityPresentationCredentialValidationOptions,
    WalletIdentityLoginOptions,
    WalletIdentityLoginResult
} from './types'

const ALLOWED_SCOPES: IdentityPresentationScope[] = [
    'identity.basic',
    'identity.wallet',
    'identity.username',
    'identity.email',
    'identity.avatar'
]

function normalizeScopes(scopes: readonly string[]) {
    const values = [...new Set(scopes.map((value) => String(value || '').trim()))]
    if (values.length === 0) throw new Error('IDENTITY_SCOPE_REQUIRED')
    for (const value of values)
        if (!ALLOWED_SCOPES.includes(value as IdentityPresentationScope)) throw new Error('IDENTITY_SCOPE_UNSUPPORTED')
    if (!values.includes('identity.basic')) values.unshift('identity.basic')
    return values as IdentityPresentationScope[]
}

function required(value: unknown, name: string) {
    const normalized = String(value || '').trim()
    if (!normalized) throw new Error(`${name} is required`)
    return normalized
}

function canonicalize(value: unknown): string {
    if (value === null) return 'null'
    if (typeof value === 'number') {
        if (!Number.isFinite(value)) throw new Error('IDENTITY_CANONICALIZATION_INVALID')
        return JSON.stringify(Object.is(value, -0) ? 0 : value)
    }
    if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
    if (typeof value !== 'object') throw new Error('IDENTITY_CANONICALIZATION_INVALID')
    if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
    return `{${Object.keys(value as Record<string, unknown>)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalize((value as Record<string, unknown>)[key])}`)
        .join(',')}}`
}

async function importIdentityPublicKey(publicKey: unknown): Promise<CryptoKey> {
    if (typeof publicKey === 'string') {
        return globalThis.crypto.subtle.importKey('raw', decodeBase64Url(publicKey), { name: 'Ed25519' }, false, [
            'verify'
        ])
    }
    if (publicKey && typeof publicKey === 'object') {
        return globalThis.crypto.subtle.importKey('jwk', publicKey as JsonWebKey, { name: 'Ed25519' }, false, [
            'verify'
        ])
    }
    throw new Error('IDENTITY_PRESENTATION_KEY_MISSING')
}

function findIdentityController(document: Record<string, unknown>, verificationMethod: string) {
    const controllers = Array.isArray(document.controllers) ? document.controllers : []
    const controller = controllers.find((item) => {
        if (!item || typeof item !== 'object') return false
        const value = item as Record<string, unknown>
        const controllerId = String(value.controllerId || value.id || '')
        return verificationMethod === `${document.id}#${controllerId}`
    }) as Record<string, unknown> | undefined
    return controller
}

function assertControllerPurpose(controller: Record<string, unknown> | undefined, purpose: string) {
    if (!controller || controller.status !== 'active') throw new Error('IDENTITY_CONTROLLER_UNTRUSTED')
    const purposes = Array.isArray(controller.purposes) ? controller.purposes : []
    const required = purpose === 'assertionMethod' ? 'assertion' : purpose
    if (!purposes.includes(required)) throw new Error('IDENTITY_CONTROLLER_PURPOSE_INVALID')
}

async function resolveTrustedIdentityDocument(holder: string, options: IdentityPresentationValidationOptions) {
    const document = options.trustedIdentityDocument || (await options.resolveIdentityDocument?.(holder))
    if (!document) throw new Error('IDENTITY_DOCUMENT_TRUST_REQUIRED')
    if (document.version !== 1 || document.id !== holder) throw new Error('IDENTITY_DOCUMENT_INVALID')
    if (!Number.isInteger(document.revision) || Number(document.revision) < 1)
        throw new Error('IDENTITY_DOCUMENT_INVALID')
    if (typeof document.walletIdentityId === 'string' && holder !== `did:yeying:${document.walletIdentityId}`)
        throw new Error('IDENTITY_DOCUMENT_INVALID')
    return document
}

async function verifyTrustedIdentityDocument(document: Record<string, unknown>) {
    const proof = document.proof as Record<string, unknown> | undefined
    if (
        !proof ||
        proof.type !== 'YeyingIdentityDocumentProofV1' ||
        typeof proof.verificationMethod !== 'string' ||
        typeof proof.proofValue !== 'string'
    )
        throw new Error('IDENTITY_DOCUMENT_PROOF_INVALID')
    const purpose = String(proof.purpose || '')
    const controller = findIdentityController(document, proof.verificationMethod)
    assertControllerPurpose(controller, purpose)
    const { proof: ignored, ...unsigned } = document
    const key = await importIdentityPublicKey(controller?.publicKey)
    const valid = await globalThis.crypto.subtle.verify(
        { name: 'Ed25519' },
        key,
        decodeBase64Url(proof.proofValue),
        new TextEncoder().encode(canonicalize(unsigned))
    )
    if (!valid) throw new Error('IDENTITY_DOCUMENT_PROOF_INVALID')
}

function normalizePresentation(value: unknown): IdentityPresentation {
    if (!value || typeof value !== 'object') throw new Error('IDENTITY_PRESENTATION_INVALID')
    const result = value as Record<string, unknown>
    const proof = result.proof as Record<string, unknown>
    if (
        result.version !== 1 ||
        typeof result.holder !== 'string' ||
        !Array.isArray(result.scopes) ||
        !proof ||
        proof.type !== 'YeyingIdentityPresentationProofV1' ||
        proof.purpose !== 'authentication' ||
        typeof proof.verificationMethod !== 'string' ||
        typeof proof.proofValue !== 'string'
    )
        throw new Error('IDENTITY_PRESENTATION_INVALID')
    return result as unknown as IdentityPresentation
}

export async function requestIdentityPresentation(
    options: IdentityPresentationRequest & { provider?: Eip1193Provider; ensureConnected?: boolean }
): Promise<IdentityPresentation> {
    const provider = options.provider || (await requireProvider())
    if (options.ensureConnected === true) await requestAccounts({ provider })
    const scopes = normalizeScopes(options.scopes)
    const request = {
        audience: required(options.audience, 'audience'),
        nonce: required(options.nonce, 'nonce'),
        scopes,
        ...(options.appId ? { appId: options.appId } : {}),
        ...(options.account ? { account: options.account } : {}),
        ...(options.issuer ? { issuer: options.issuer } : {}),
        ...(options.issuerEndpoint ? { issuerEndpoint: options.issuerEndpoint } : {}),
        ...(options.expiresAt ? { expiresAt: options.expiresAt } : {}),
        ...(options.statement ? { statement: options.statement } : {}),
        ...(options.requestId ? { requestId: options.requestId } : {})
    }
    const response = await provider.request({ method: 'wallet_identity_presentation', params: [request] })
    return normalizePresentation(response)
}

function identityLoginUrl(baseUrl: string, path: string) {
    return `${baseUrl.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`
}

async function identityLoginPost(fetcher: typeof fetch, credentials: RequestCredentials, url: string, body: unknown) {
    const response = await fetcher(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        credentials,
        body: JSON.stringify(body)
    })
    const payload = (await response.json()) as {
        code?: number
        message?: string
        reason?: string
        data?: Record<string, any>
    }
    if (!response.ok || payload.code)
        throw Object.assign(new Error(payload.message || 'WALLET_IDENTITY_LOGIN_FAILED'), { payload })
    return payload.data || {}
}

async function requestWalletIdentityPermissions(provider: Eip1193Provider, scopes: IdentityPresentationScope[]) {
    const requestedScopes = normalizeScopes(scopes)
    const permissions = await provider.request({
        method: 'wallet_requestPermissions',
        params: [{ wallet_identity: { scopes: requestedScopes } }]
    })
    if (!Array.isArray(permissions)) throw new Error('WALLET_PERMISSIONS_INVALID')
    return permissions
}

export async function loginWithWalletIdentity(
    options: WalletIdentityLoginOptions = {}
): Promise<WalletIdentityLoginResult> {
    const provider = options.provider || (await requireProvider())
    const fetcher = options.fetcher || fetch
    const credentials = options.credentials ?? 'include'
    const baseUrl = options.baseUrl || '/api/v1/public/auth'
    const sessionUrl = identityLoginUrl(baseUrl, options.sessionPath || 'identity/login/session')
    const verifyUrl = identityLoginUrl(baseUrl, options.verifyPath || 'identity/login/verify')
    const session = await identityLoginPost(fetcher, credentials, sessionUrl, {})
    const requestedScopes = options.scopes ? normalizeScopes(options.scopes) : null
    const scopes = normalizeScopes(session.scopes || requestedScopes || ['identity.basic'])
    if (
        requestedScopes &&
        (requestedScopes.length !== scopes.length || requestedScopes.some((scope) => !scopes.includes(scope)))
    )
        throw new Error('IDENTITY_SCOPE_MISMATCH')
    await requestWalletIdentityPermissions(provider, scopes)
    const appId = session.app_id || session.appId
    const issuerEndpoint = session.issuerEndpoint
    const presentation = await requestIdentityPresentation({
        provider,
        ...(appId ? { appId } : {}),
        ...(issuerEndpoint ? { issuerEndpoint } : {}),
        audience: session.audience,
        nonce: session.nonce,
        scopes,
        requestId: session.request_id || session.requestId,
        ensureConnected: false
    })
    const result = await identityLoginPost(fetcher, credentials, verifyUrl, {
        session_id: session.session_id,
        request_id: session.request_id,
        presentation
    })
    const token = String(result.token || '')
    if (!token) throw new Error('WALLET_IDENTITY_TOKEN_MISSING')
    if (options.storeToken !== false) setAccessToken(token, options)
    const did = String(result.did || presentation.holder || '')
    if (!did) throw new Error('WALLET_IDENTITY_DID_MISSING')
    const walletAddress = String(result.walletAddress || result.wallet_address || '')
    return { token, did, ...(walletAddress ? { walletAddress } : {}), response: result }
}

export async function verifyIdentityPresentation(
    presentation: unknown,
    options: IdentityPresentationValidationOptions
): Promise<IdentityPresentation> {
    const value = normalizePresentation(presentation)
    const skew = Math.max(0, options.clockSkewSeconds ?? 60)
    if (value.audience !== options.expectedAudience || value.nonce !== options.expectedNonce)
        throw new Error('IDENTITY_PRESENTATION_CONTEXT_MISMATCH')
    const requested = new Set(value.scopes)
    for (const scope of options.expectedScopes || [])
        if (!requested.has(scope)) throw new Error('IDENTITY_PRESENTATION_SCOPE_MISMATCH')
    const issued = Date.parse(value.issuedAt)
    const expires = Date.parse(value.expiresAt)
    const now = (options.now ?? Date.now() / 1000) * 1000
    if (
        !Number.isFinite(issued) ||
        !Number.isFinite(expires) ||
        issued > now + skew * 1000 ||
        expires <= now - skew * 1000
    )
        throw new Error('IDENTITY_PRESENTATION_EXPIRED')
    const method = value.proof.verificationMethod
    const embeddedDocument = value.identityDocument as Record<string, unknown> | undefined
    if (!embeddedDocument || embeddedDocument.id !== value.holder) throw new Error('IDENTITY_DOCUMENT_INVALID')
    const trustedDocument = await resolveTrustedIdentityDocument(value.holder, options)
    if (canonicalize(embeddedDocument) !== canonicalize(trustedDocument))
        throw new Error('IDENTITY_DOCUMENT_MISMATCH')
    await verifyTrustedIdentityDocument(trustedDocument)
    const controller = findIdentityController(trustedDocument, method)
    assertControllerPurpose(controller, 'authentication')
    const { proof, ...unsigned } = value as unknown as Record<string, unknown>
    try {
        const key = await importIdentityPublicKey(controller?.publicKey)
        const valid = await globalThis.crypto.subtle.verify(
            { name: 'Ed25519' },
            key,
            decodeBase64Url(value.proof.proofValue),
            new TextEncoder().encode(canonicalize(unsigned))
        )
        if (!valid) throw new Error('IDENTITY_PRESENTATION_PROOF_INVALID')
    } catch (error) {
        if (error instanceof Error && error.message === 'IDENTITY_PRESENTATION_PROOF_INVALID') throw error
        throw new Error('IDENTITY_PRESENTATION_PROOF_INVALID')
    }
    return value
}

export async function verifyIdentityPresentationCredentials(
    presentation: unknown,
    options: IdentityPresentationCredentialValidationOptions
) {
    const value = await verifyIdentityPresentation(presentation, options)
    const credentials = value.credentials || []
    const requiredTypes = (options.expectedScopes || value.scopes)
        .filter(
            (scope) =>
                scope === 'identity.wallet' ||
                scope === 'identity.email' ||
                scope === 'identity.username' ||
                scope === 'identity.avatar'
        )
        .map((scope) => {
            if (scope === 'identity.wallet') return 'WalletAccountCredential' as const
            if (scope === 'identity.email') return 'EmailCredential' as const
            if (scope === 'identity.username') return 'UsernameCredential' as const
            return 'AvatarCredential' as const
        })
    const uniqueTypes = [...new Set(requiredTypes)]
    const validations = []
    for (const expectedType of uniqueTypes) {
        const token = credentials.find((item) => {
            try {
                return (
                    (decodeIdentityCredential(item).payload.vc as Record<string, unknown> | undefined)?.type instanceof
                        Array &&
                    ((decodeIdentityCredential(item).payload.vc as Record<string, unknown>).type as unknown[]).includes(
                        expectedType
                    )
                )
            } catch {
                return false
            }
        })
        if (!token) throw new Error(`IDENTITY_CREDENTIAL_MISSING:${expectedType}`)
        validations.push(
            await verifyIdentityCredential(token, {
                issuer: options.issuer,
                publicJwk: options.publicJwk,
                expectedSubject: value.holder,
                expectedType,
                now: options.now
            })
        )
    }
    if (uniqueTypes.includes('WalletAccountCredential')) {
        const proof = value.walletProof
        const chainKey = String(proof?.chainKey || '')
        const address = String(proof?.address || '').toLowerCase()
        if (!/^eip155:[0-9]+$/.test(chainKey) || !/^0x[0-9a-f]{40}$/.test(address))
            throw new Error('IDENTITY_WALLET_PROOF_INVALID')
        const validation = validations.find((item) => item.credentialType === 'WalletAccountCredential')
        const subject = validation?.payload?.vc as Record<string, unknown> | undefined
        const claims = subject?.credentialSubject as Record<string, unknown> | undefined
        if (claims?.chainKey !== chainKey || String(claims?.address || '').toLowerCase() !== address)
            throw new Error('IDENTITY_WALLET_PROOF_MISMATCH')
    }
    let status: CredentialStatusResponse | undefined
    if (options.nodeBaseUrl) {
        status = await queryCredentialStatuses(
            options.nodeBaseUrl,
            options.issuer,
            validations.map((item) => item.credentialId),
            options.fetcher
        )
        for (const item of validations)
            if (status.statuses[item.credentialId] !== 'active')
                throw new Error(`IDENTITY_CREDENTIAL_NOT_ACTIVE:${item.credentialId}`)
    }
    return { presentation: value, credentials: validations, status }
}
