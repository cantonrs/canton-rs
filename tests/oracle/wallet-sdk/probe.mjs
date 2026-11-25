// G10 (S-SDK-001, U-25): the official Canton Wallet SDK (pinned in package.json) driven against a Ledger API JSON v2 server, step by step.
// Every step is recorded as {step, ok, detail}; a step that fails does not stop the next ones. Run by scripts/verify-wallet-sdk.sh.
//   node probe.mjs <ledger-json-api-url>
import { SDK } from '@canton-network/wallet-sdk'
import { createHmac } from 'node:crypto'

const url = process.argv[2]
// TRACE_FILE=<path>: every HTTP exchange of the run (the SDK's and this script's) as one JSON line {method, path, status, shape}, `shape` being the
// response's keys (objects) or its first element's keys (arrays), so two servers can be compared without their ids and times.
import { appendFileSync, writeFileSync } from 'node:fs'
if (process.env.TRACE_FILE) {
    writeFileSync(process.env.TRACE_FILE, '')
    const shape = (v, depth = 0) => (Array.isArray(v) ? [v.length ? shape(v[0], depth + 1) : null] : v && typeof v === 'object' && depth < 4 ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, shape(v[k], depth + 1)])) : typeof v)
    const realFetch = globalThis.fetch
    globalThis.fetch = async (input, init) => {
        const res = await realFetch(input, init)
        try {
            const u = new URL(typeof input === 'string' || input instanceof URL ? input : input.url)
            const text = await res.clone().text()
            let body
            try { body = JSON.parse(text) } catch { body = text.slice(0, 0) }
            appendFileSync(process.env.TRACE_FILE, JSON.stringify({ method: (init?.method ?? (typeof input === 'object' && 'method' in input ? input.method : undefined) ?? 'GET').toUpperCase(), path: u.pathname, status: res.status, shape: shape(body) }) + '\n')
        } catch {}
        return res
    }
}
// With AUTH_SECRET the server checks JWTs (`--jwt-hmac-secret`): the requests this script makes itself carry a token, as the SDK's own do.
const secret = process.env.AUTH_SECRET
const b64u = (x) => Buffer.from(x).toString('base64url')
const token = (sub) => {
    const head = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    const body = b64u(JSON.stringify({ sub, aud: 'https://canton.network.global', exp: Math.floor(Date.now() / 1000) + 240 }))
    return `${head}.${body}.${createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url')}`
}
const headers = (sub) => ({ 'Content-Type': 'application/json', ...(secret ? { Authorization: `Bearer ${token(sub)}` } : {}) })
const results = []
// `knownGap`: the id of a gap recorded in doc/slices/UNRESOLVED.md that this step shows; the step still fails (ok: false) so the gap stays visible, and the
// scripts that run this probe do not count it as a failed run.
async function step(name, fn, knownGap) {
    try {
        const detail = await fn()
        results.push({ step: name, ok: true, detail })
    } catch (e) {
        const text = typeof e === 'object' ? JSON.stringify(e, Object.getOwnPropertyNames(e ?? {})) : String(e)
        results.push({ step: name, ok: false, detail: text.slice(0, 700), ...(knownGap ? { knownGap } : {}) })
    }
}

// The user the SDK's self-signed token names (`sub` = clientId) has to exist on the participant, as it does on the official LocalNet: created here
// with participant admin rights through the plain JSON API (not an SDK call).
await step('setup: user ledger-api-user with ParticipantAdmin', async () => {
    const r = await fetch(`${url}/v2/users`, {
        method: 'POST',
        headers: headers('participant_admin'),
        body: JSON.stringify({
            user: { id: 'ledger-api-user', isDeactivated: false, primaryParty: '', identityProviderId: '', metadata: { resourceVersion: '', annotations: {} } },
            rights: [{ kind: { ParticipantAdmin: { value: {} } } }],
        }),
    })
    if (r.status === 409) return 'exists already'
    if (!r.ok) throw new Error(`POST /v2/users answered ${r.status}: ${(await r.text()).slice(0, 300)}`)
    return r.status
})

// EXPECT_REFUSED=1: the SDK signs its token with a secret the server does not know; every call has to be refused (exit 0 when it is)
if (process.env.EXPECT_REFUSED) {
    try {
        const refused = await SDK.create({
            auth: { method: 'self_signed', issuer: 'unsafe-auth', credentials: { clientId: 'ledger-api-user', clientSecret: 'not-the-secret', audience: 'https://canton.network.global', scope: '' } },
            ledgerClientUrl: url,
        })
        await refused.ledger.ledgerEnd()
        console.log(JSON.stringify([{ step: 'a token signed with another secret is refused', ok: false, detail: 'the server answered' }], null, 1))
        process.exit(1)
    } catch (e) {
        console.log(JSON.stringify([{ step: 'a token signed with another secret is refused', ok: true, detail: String(e?.message ?? e).slice(0, 120) }], null, 1))
        process.exit(0)
    }
}

let sdk
await step('SDK.create', async () => {
    sdk = await SDK.create({
        auth: {
            method: 'self_signed',
            issuer: 'unsafe-auth',
            credentials: { clientId: 'ledger-api-user', clientSecret: 'unsafe', audience: 'https://canton.network.global', scope: '' },
        },
        ledgerClientUrl: url,
    })
    return Object.keys(sdk).sort()
})
if (sdk) {
    await step('ledger.ledgerEnd', async () => ({ offset: await sdk.ledger.ledgerEnd() }))
    await step('ledger.connectedSynchronizers', async () => (await sdk.ledger.connectedSynchronizers()).connectedSynchronizers?.length)
    await step('party.list (before)', async () => (await sdk.party.list()).length)
    let keys, created
    await step('keys.generate', async () => {
        keys = sdk.keys.generate()
        return { fingerprint: await sdk.keys.fingerprint(keys.publicKey) }
    })
    if (keys) {
        await step('party.external.create(...).sign(...).execute()', async () => {
            created = await sdk.party.external.create(keys.publicKey, { partyHint: 'sdkwallet' }).sign(keys.privateKey).execute()
            return { partyId: created.partyId, fingerprint: created.publicKeyFingerprint }
        })
    }
    // REFERENCE_ONLY=1 (a server without the sample DAR, e.g. the official Splice LocalNet): the steps that need that DAR are left out
    if (created && !process.env.REFERENCE_ONLY) {
        const partyId = created.partyId
        const template = '#sample-contract:AssetHolding:AssetHolding'
        const commands = [{ CreateCommand: { templateId: template, createArguments: { bank: partyId, owner: partyId, auditor: partyId, assetSymbol: 'USD', amount: '5.0' } } }]
        let prepared
        await step('ledger.prepare (interactive submission, create)', async () => {
            prepared = sdk.ledger.prepare({ partyId, commands, commandId: 'sdk-probe-1' })
            const { response } = await prepared.toJSON()
            return { hashingSchemeVersion: response.hashingSchemeVersion, hashBytes: Buffer.from(response.preparedTransactionHash, 'base64').length }
        })
        if (prepared) {
            // the SDK's own implementation of the transaction hash (core-tx-hashing) against the one the server prepared
            await step('SDK recomputes the prepared transaction hash = the server hash', async () => {
                const { response } = await prepared.toJSON()
                const mine = (await sdk.utils.hash.preparedTransaction(response.preparedTransaction, response.hashingSchemeVersion)).toBase64()
                if (mine !== response.preparedTransactionHash) throw new Error(`SDK hash ${mine} != server hash ${response.preparedTransactionHash}`)
                return { scheme: response.hashingSchemeVersion, hash: mine }
            })
            // the same command prepared with the V3 hashing scheme (the SDK's prepare does not ask for it: a plain request), and the SDK's V3 hash
            await step('V3: the server prepares with HASHING_SCHEME_VERSION_V3 and the SDK recomputes the same hash', async () => {
                const synchronizerId = (await sdk.ledger.connectedSynchronizers()).connectedSynchronizers[0].synchronizerId
                const r = await fetch(`${url}/v2/interactive-submission/prepare`, {
                    method: 'POST',
                    headers: headers('ledger-api-user'),
                    body: JSON.stringify({
                        userId: 'ledger-api-user', commandId: 'sdk-probe-v3', commands, actAs: [partyId], readAs: [],
                        packageIdSelectionPreference: [], verboseHashing: false, synchronizerId, hashingSchemeVersion: 'HASHING_SCHEME_VERSION_V3',
                    }),
                })
                const text = await r.text()
                if (!r.ok) throw new Error(`prepare answered ${r.status}: ${text.slice(0, 500)}`)
                const body = JSON.parse(text)
                if (body.hashingSchemeVersion !== 'HASHING_SCHEME_VERSION_V3') throw new Error(`the server prepared with ${body.hashingSchemeVersion}`)
                const mine = (await sdk.utils.hash.preparedTransaction(body.preparedTransaction, 'HASHING_SCHEME_VERSION_V3')).toBase64()
                if (mine !== body.preparedTransactionHash) throw new Error(`SDK V3 hash ${mine} != server hash ${body.preparedTransactionHash}`)
                return { scheme: body.hashingSchemeVersion, hash: mine }
            })
            await step('SDK decodes the prepared transaction', async () => {
                const decoded = await prepared.decode()
                return { nodes: decoded.transaction?.nodes?.length ?? null }
            })
            await step('sign + ledger.execute (executeAndWait)', async () => {
                const signed = prepared.sign(keys.privateKey)
                return await sdk.ledger.execute(signed, { partyId })
            })
            // negative control: a signature of another key must be refused (the party's key is the one in its topology)
            await step('negative: a signature of another key is refused', async () => {
                const second = sdk.ledger.prepare({ partyId, commands, commandId: 'sdk-probe-2' })
                const stranger = sdk.keys.generate()
                try {
                    await sdk.ledger.execute(second.sign(stranger.privateKey), { partyId })
                } catch (e) {
                    return { refused: true, code: e?.context?.originalError?.code ?? e?.code ?? null }
                }
                throw new Error('the submission signed with another key was accepted')
            })
            await step('acs.read shows the contract the signed submission made', async () => {
                const acs = await sdk.ledger.acs.read({ parties: [partyId], filterByParty: true })
                return { count: acs.length, templates: acs.map((c) => c.templateId.split(':').slice(1).join(':')) }
            })
        }
    }
    await step('party.list (after)', async () => {
        const parties = await sdk.party.list()
        return { count: parties.length, containsCreated: created ? parties.includes(created.partyId) : null }
    })
}
// U-25 (Token Standard): with AMULET_SCAN_URL the SDK also gets the `amulet` extension (scan + registry at that URL, `/api/scan`), and an external party taps
// DevNet Amulet: `amulet.tap` reads AmuletRules and the open mining round from scan and the transfer factory context from the registry, the SDK prepares and
// signs the exercise of `AmuletRules_DevNet_Tap` (the scan's contracts disclosed), the participant executes it, and the new holding shows in the ACS.
if (process.env.AMULET_SCAN_URL && sdk) {
    const scan = `${process.env.AMULET_SCAN_URL}/api/scan`
    let amulet
    await step('SDK.create with the amulet extension (scanApiUrl, registryUrl)', async () => {
        const auth = { method: 'self_signed', issuer: 'unsafe-auth', credentials: { clientId: 'ledger-api-user', clientSecret: 'unsafe', audience: 'https://canton.network.global', scope: '' } }
        amulet = await SDK.create({ auth, ledgerClientUrl: url, amulet: { auth, scanApiUrl: scan, registryUrl: process.env.AMULET_SCAN_URL }, token: { auth, registries: [process.env.AMULET_SCAN_URL] } })
        return Object.keys(amulet).sort()
    })
    if (amulet) {
        await step('amulet.isDevNet (scan /v0/dso + AmuletRules)', async () => ({ isDevNet: await amulet.amulet.isDevNet() }))
        const keys = amulet.keys.generate()
        let party
        await step('amulet: external party for the holder', async () => {
            party = await amulet.party.external.create(keys.publicKey, { partyHint: 'sdkholder' }).sign(keys.privateKey).execute()
            return { partyId: party.partyId }
        })
        if (party) {
            const partyId = party.partyId
            await step('amulet.tap: prepare, sign, execute (DevNet tap of 100 for the external party)', async () => {
                const [command, disclosedContracts] = await amulet.amulet.tap(partyId, '100')
                const prepared = amulet.ledger.prepare({ partyId, commands: [command], disclosedContracts, commandId: 'sdk-amulet-tap-1' })
                const { response } = await prepared.toJSON()
                const mine = (await amulet.utils.hash.preparedTransaction(response.preparedTransaction, response.hashingSchemeVersion)).toBase64()
                if (mine !== response.preparedTransactionHash) throw new Error(`SDK hash ${mine} != server hash ${response.preparedTransactionHash}`)
                const done = await amulet.ledger.execute(prepared.sign(keys.privateKey), { partyId })
                return { disclosed: disclosedContracts.length, hashAgrees: true, done }
            })
            await step('amulet: the holding is in the ACS (Splice.Amulet:Amulet of the holder, 100)', async () => {
                const acs = await amulet.ledger.acs.read({ parties: [partyId], filterByParty: true })
                const holdings = acs.filter((c) => c.templateId.endsWith(':Splice.Amulet:Amulet'))
                if (holdings.length !== 1) throw new Error(`expected 1 Amulet, found ${holdings.length}: ${acs.map((c) => c.templateId)}`)
                return { amount: holdings[0].createArgument?.amount?.initialAmount ?? holdings[0].createArgument }
            })
            await step('token.utxos.list: the Holding interface view of the holder (amount 100, instrument Amulet)', async () => {
                const utxos = await amulet.token.utxos.list({ partyId })
                if (utxos.length !== 1) throw new Error(`expected 1 holding, found ${utxos.length}`)
                const view = utxos[0].interfaceViewValue
                return { owner: view?.owner === partyId, amount: view?.amount, instrument: view?.instrumentId?.id }
            })
            // a Token Standard transfer of 10 Amulet from the holder to a second external party: the SDK asks the registry for the factory and its
            // choice context, prepares `TransferFactory_Transfer` with the holder's UTXOs, the holder signs, and the offer is pending for the recipient
            const bobKeys = amulet.keys.generate()
            let bob
            await step('amulet: a second external party (the recipient)', async () => {
                bob = await amulet.party.external.create(bobKeys.publicKey, { partyHint: 'sdkrecipient' }).sign(bobKeys.privateKey).execute()
                return { partyId: bob.partyId }
            })
            if (bob) {
                await step('token.transfer.create: the holder sends 10 Amulet to the recipient (prepare, sign, execute)', async () => {
                    const [command, disclosedContracts] = await amulet.token.transfer.create({ sender: partyId, recipient: bob.partyId, amount: '10', instrumentId: 'Amulet', registryUrl: process.env.AMULET_SCAN_URL })
                    const prepared = amulet.ledger.prepare({ partyId, commands: [command], disclosedContracts, commandId: 'sdk-amulet-transfer-1' })
                    const { response } = await prepared.toJSON()
                    // DUMP_PREPARED=<file>: the decoded prepared transaction, to compare its structure with the other server's
                    if (process.env.DUMP_PREPARED) {
                        writeFileSync(process.env.DUMP_PREPARED, JSON.stringify(await prepared.decode(), (k, v) => (typeof v === 'bigint' ? v.toString() : v), 1))
                        writeFileSync(`${process.env.DUMP_PREPARED}.raw.json`, JSON.stringify({ preparedTransaction: response.preparedTransaction, preparedTransactionHash: response.preparedTransactionHash, hashingSchemeVersion: response.hashingSchemeVersion }))
                    }
                    const mine = (await amulet.utils.hash.preparedTransaction(response.preparedTransaction, response.hashingSchemeVersion)).toBase64()
                    if (mine !== response.preparedTransactionHash) throw new Error(`SDK hash ${mine} != server hash ${response.preparedTransactionHash}`)
                    const done = await amulet.ledger.execute(prepared.sign(keys.privateKey), { partyId })
                    return { disclosed: disclosedContracts.length, hashAgrees: true, done }
                })
                let pendingCid
                await step('token.transfer.pending: the offer is pending for the recipient', async () => {
                    const pending = await amulet.token.transfer.pending(bob.partyId)
                    pendingCid = pending[0]?.contractId
                    return { count: pending.length, amount: pending[0]?.interfaceViewValue?.transfer?.amount }
                })
                // the recipient accepts the offer: the SDK asks the registry for the accept choice context, the recipient signs
                if (pendingCid) {
                    await step('token.transfer.accept: the recipient accepts the offer (prepare, sign, execute)', async () => {
                        const [command, disclosedContracts] = await amulet.token.transfer.accept({ transferInstructionCid: pendingCid, registryUrl: process.env.AMULET_SCAN_URL })
                        const prepared = amulet.ledger.prepare({ partyId: bob.partyId, commands: [command], disclosedContracts, commandId: 'sdk-amulet-accept-1' })
                        const { response } = await prepared.toJSON()
                        if (process.env.DUMP_PREPARED) writeFileSync(`${process.env.DUMP_PREPARED}.accept.json`, JSON.stringify(await prepared.decode(), (k, v) => (typeof v === 'bigint' ? v.toString() : v), 1))
                        const mine = (await amulet.utils.hash.preparedTransaction(response.preparedTransaction, response.hashingSchemeVersion)).toBase64()
                        if (mine !== response.preparedTransactionHash) throw new Error(`SDK hash ${mine} != server hash ${response.preparedTransactionHash}`)
                        const done = await amulet.ledger.execute(prepared.sign(bobKeys.privateKey), { partyId: bob.partyId })
                        return { disclosed: disclosedContracts.length, hashAgrees: true, done }
                    })
                    await step('token.utxos.list: the recipient holds 10 Amulet, the holder 90 (change)', async () => {
                        const mine = await amulet.token.utxos.list({ partyId })
                        const theirs = await amulet.token.utxos.list({ partyId: bob.partyId })
                        const sum = (l) => l.reduce((a, u) => a + Number(u.interfaceViewValue.amount), 0)
                        if (sum(theirs) !== 10 || sum(mine) !== 90) throw new Error(`holder ${sum(mine)}, recipient ${sum(theirs)}`)
                        return { holder: sum(mine), recipient: sum(theirs) }
                    })
                }
            }
            await step('token.holdings: the token standard view of the holder', async () => {
                const holdings = await amulet.token.holdings({ partyId })
                const txs = holdings?.transactions
                if (!Array.isArray(txs) || txs.length < 2) {
                    throw new Error(`expected >= 2 holding transactions for ${partyId}, got ${JSON.stringify(holdings)}`)
                }
                return {
                    nextOffset: holdings.nextOffset,
                    count: txs.length,
                    labels: txs.flatMap((t) => (t.events ?? []).map((e) => e.label?.type)),
                }
            }, process.env.KNOWN_GAP_TOKEN_HOLDINGS)
        }
    }
}

console.log(JSON.stringify(results, null, 1))
process.exit(results.every((r) => r.ok || r.knownGap) ? 0 : 1)
