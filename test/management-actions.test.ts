import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startMock, type Harness } from './helpers.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const uuid = () => expect.stringMatching(UUID);
const iso = () => expect.stringMatching(ISO);

const CODE_V1 = 'exports.onExecutePostLogin = async (event, api) => {};';
const CODE_V2 = 'exports.onExecutePostLogin = async (event, api) => { api.idToken.setCustomClaim("v", 2); };';
const POST_LOGIN = [{ id: 'post-login', version: 'v3' }];
const envelope = (key: string, items: unknown[], overrides: Record<string, unknown> = {}) => ({
    [key]: items,
    total: items.length,
    per_page: 20,
    page: 0,
    start: 0,
    limit: 20,
    length: items.length,
    ...overrides,
});

describe('Actions', () => {
    let h: Harness;
    let action: Record<string, any>;
    let minimal: Record<string, any>;
    beforeAll(async () => {
        h = await startMock();
    });
    afterAll(() => h.close());

    it('POST creates a built action and returns secrets as {name, updated_at} only', async () => {
        const res = await h.mgmt('POST', '/actions/actions', {
            name: 'Add claims',
            supported_triggers: POST_LOGIN,
            code: CODE_V1,
            runtime: 'node22',
            dependencies: [{ name: 'auth0', version: '4.3.1' }, { name: 'lodash' }],
            secrets: [{ name: 'API_KEY', value: 'shh-secret' }],
        });
        expect(res.status).toBe(201);
        expect(res.body).toEqual({
            id: uuid(),
            name: 'Add claims',
            supported_triggers: POST_LOGIN,
            code: CODE_V1,
            dependencies: [
                { name: 'auth0', version: '4.3.1' },
                { name: 'lodash', version: 'latest' },
            ],
            runtime: 'node22',
            secrets: [{ name: 'API_KEY', updated_at: iso() }],
            status: 'built',
            all_changes_deployed: false,
            built_at: iso(),
            created_at: iso(),
            updated_at: iso(),
        });
        expect(res.body).not.toHaveProperty('deployed_version');
        expect(JSON.stringify(res.body)).not.toContain('shh-secret');
        action = res.body;

        const minimalRes = await h.mgmt('POST', '/actions/actions', {
            name: 'Minimal',
            supported_triggers: [{ id: 'credentials-exchange' }],
        });
        expect(minimalRes.status).toBe(201);
        expect(minimalRes.body).toMatchObject({
            code: '',
            dependencies: [],
            runtime: 'node22',
            secrets: [],
            supported_triggers: [{ id: 'credentials-exchange', version: 'v2' }],
            status: 'built',
            all_changes_deployed: false,
        });
        minimal = minimalRes.body;
    });

    it('validates the payload', async () => {
        const duplicate = await h.mgmt('POST', '/actions/actions', {
            name: 'Add claims',
            supported_triggers: POST_LOGIN,
        });
        expect(duplicate.status).toBe(409);
        expect(duplicate.body).toEqual({
            statusCode: 409,
            error: 'Conflict',
            message: "An action with the name 'Add claims' already exists",
            errorCode: 'action_conflict',
        });

        const noTriggers = await h.mgmt('POST', '/actions/actions', { name: 'x' });
        expect(noTriggers.status).toBe(400);
        expect(noTriggers.body.message).toBe(
            "Payload validation error: 'supported_triggers' must be a non-empty array"
        );
        expect((await h.mgmt('POST', '/actions/actions', { name: 'x', supported_triggers: [] })).status).toBe(400);

        const unknownTrigger = await h.mgmt('POST', '/actions/actions', {
            name: 'x',
            supported_triggers: [{ id: 'nope' }],
        });
        expect(unknownTrigger.status).toBe(400);
        expect(unknownTrigger.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Unknown trigger 'nope'",
            errorCode: 'invalid_trigger',
        });
        const unknownVersion = await h.mgmt('POST', '/actions/actions', {
            name: 'x',
            supported_triggers: [{ id: 'post-login', version: 'v9' }],
        });
        expect(unknownVersion.status).toBe(400);
        expect(unknownVersion.body.message).toBe("Unknown trigger 'post-login' v9");

        const badSecrets = await h.mgmt('POST', '/actions/actions', {
            name: 'x',
            supported_triggers: POST_LOGIN,
            secrets: [{ value: 'no name' }],
        });
        expect(badSecrets.status).toBe(400);
        expect(badSecrets.body.message).toBe("Payload validation error: each secret requires a 'name'");
        const badDependencies = await h.mgmt('POST', '/actions/actions', {
            name: 'x',
            supported_triggers: POST_LOGIN,
            dependencies: 'auth0',
        });
        expect(badDependencies.status).toBe(400);
        expect(badDependencies.body.message).toBe("Payload validation error: 'dependencies' must be an array");
        const noName = await h.mgmt('POST', '/actions/actions', { supported_triggers: POST_LOGIN });
        expect(noName.status).toBe(400);
        expect((await h.mgmt('GET', '/actions/actions')).body.total).toBe(2);
    });

    it('GET list returns the Actions envelope and supports triggerId/actionName/deployed filters', async () => {
        const list = await h.mgmt('GET', '/actions/actions');
        expect(list.status).toBe(200);
        expect(list.body).toEqual(envelope('actions', [expect.any(Object), expect.any(Object)]));
        expect(list.body.actions.map((a: { name: string }) => a.name).sort()).toEqual(['Add claims', 'Minimal']);
        expect(list.body.actions.find((a: { id: string }) => a.id === action.id)).toEqual(action);

        const byTrigger = await h.mgmt('GET', '/actions/actions?triggerId=post-login');
        expect(byTrigger.body).toEqual(envelope('actions', [action]));
        expect((await h.mgmt('GET', '/actions/actions?triggerId=credentials-exchange')).body.actions).toEqual([
            minimal,
        ]);
        expect((await h.mgmt('GET', '/actions/actions?triggerId=nope')).body).toEqual(envelope('actions', []));

        const byName = await h.mgmt('GET', '/actions/actions?actionName=Minimal');
        expect(byName.body.actions).toEqual([minimal]);
        expect((await h.mgmt('GET', '/actions/actions?actionName=minimal')).body.total).toBe(0);

        expect((await h.mgmt('GET', '/actions/actions?deployed=true')).body).toEqual(envelope('actions', []));
        expect((await h.mgmt('GET', '/actions/actions?deployed=false')).body.total).toBe(2);

        const paged = await h.mgmt('GET', '/actions/actions?per_page=1&page=1');
        expect(paged.body).toMatchObject({ total: 2, per_page: 1, page: 1, start: 1, limit: 1, length: 1 });
        expect(paged.body.actions).toHaveLength(1);
        expect((await h.mgmt('GET', '/actions/actions?per_page=101')).status).toBe(400);
    });

    it('GET by id', async () => {
        const got = await h.mgmt('GET', `/actions/actions/${action.id}`);
        expect(got.status).toBe(200);
        expect(got.body).toEqual(action);
        const missing = await h.mgmt('GET', '/actions/actions/nope');
        expect(missing.status).toBe(404);
        expect(missing.body).toEqual({
            statusCode: 404,
            error: 'Not Found',
            message: 'The action does not exist',
            errorCode: 'inexistent_resource',
        });
    });

    it('POST deploy creates version 1 and marks all changes deployed', async () => {
        const res = await h.mgmt('POST', `/actions/actions/${action.id}/deploy`);
        expect(res.status).toBe(200);
        expect(res.body).toEqual({
            id: uuid(),
            action_id: action.id,
            code: CODE_V1,
            dependencies: action.dependencies,
            runtime: 'node22',
            secrets: [{ name: 'API_KEY', updated_at: iso() }],
            status: 'built',
            number: 1,
            deployed: true,
            built_at: iso(),
            created_at: iso(),
            updated_at: iso(),
            supported_triggers: POST_LOGIN,
            action: expect.objectContaining({ id: action.id, name: 'Add claims', supported_triggers: POST_LOGIN }),
        });
        expect(res.body.action).not.toHaveProperty('code');
        expect(res.body.action).not.toHaveProperty('secrets');
        expect(JSON.stringify(res.body)).not.toContain('shh-secret');

        const got = await h.mgmt('GET', `/actions/actions/${action.id}`);
        expect(got.body.all_changes_deployed).toBe(true);
        expect(got.body.deployed_version).toMatchObject({ id: res.body.id, number: 1, deployed: true, code: CODE_V1 });
        expect(got.body.deployed_version.secrets).toEqual([{ name: 'API_KEY', updated_at: iso() }]);
        // current_version mirrors deployed_version and must be sanitised the same way.
        expect(got.body.current_version).toEqual(got.body.deployed_version);
        expect(got.body.current_version.secrets).toEqual([{ name: 'API_KEY', updated_at: iso() }]);
        expect(JSON.stringify(got.body)).not.toContain('shh-secret');

        expect(
            (await h.mgmt('GET', '/actions/actions?deployed=true')).body.actions.map((a: { id: string }) => a.id)
        ).toEqual([action.id]);
        expect((await h.mgmt('GET', '/actions/actions?deployed=false')).body.actions).toEqual([minimal]);
        expect((await h.mgmt('POST', '/actions/actions/nope/deploy')).status).toBe(404);
    });

    it('PATCH code marks changes undeployed; PATCH name alone does not', async () => {
        const renamed = await h.mgmt('PATCH', `/actions/actions/${action.id}`, { name: 'Add claims v2' });
        expect(renamed.status).toBe(200);
        expect(renamed.body.name).toBe('Add claims v2');
        expect(renamed.body.all_changes_deployed).toBe(true);

        const patched = await h.mgmt('PATCH', `/actions/actions/${action.id}`, {
            code: CODE_V2,
            secrets: [{ name: 'API_KEY' }, { name: 'OTHER', value: 'x' }],
        });
        expect(patched.status).toBe(200);
        expect(patched.body).toMatchObject({
            name: 'Add claims v2',
            code: CODE_V2,
            all_changes_deployed: false,
            status: 'built',
        });
        expect(patched.body.secrets).toEqual([
            { name: 'API_KEY', updated_at: action.secrets[0].updated_at },
            { name: 'OTHER', updated_at: iso() },
        ]);
        expect(patched.body.deployed_version).toMatchObject({ number: 1, code: CODE_V1 });
        expect(JSON.stringify(patched.body)).not.toContain('shh-secret');

        const clash = await h.mgmt('PATCH', `/actions/actions/${action.id}`, { name: 'Minimal' });
        expect(clash.status).toBe(409);
        expect(clash.body.errorCode).toBe('action_conflict');
        const badTrigger = await h.mgmt('PATCH', `/actions/actions/${action.id}`, {
            supported_triggers: [{ id: 'nope' }],
        });
        expect(badTrigger.status).toBe(400);
        expect(badTrigger.body.errorCode).toBe('invalid_trigger');
        expect((await h.mgmt('PATCH', `/actions/actions/${action.id}`, { code: 42 })).status).toBe(400);
        expect((await h.mgmt('PATCH', '/actions/actions/nope', { name: 'x' })).status).toBe(404);
        expect((await h.mgmt('GET', `/actions/actions/${action.id}`)).body.name).toBe('Add claims v2');
    });

    it('a second deploy creates version 2 and lists versions newest first', async () => {
        const res = await h.mgmt('POST', `/actions/actions/${action.id}/deploy`);
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ number: 2, deployed: true, code: CODE_V2, action_id: action.id });
        expect(res.body.secrets.map((s: { name: string }) => s.name)).toEqual(['API_KEY', 'OTHER']);
        expect(res.body.action.name).toBe('Add claims v2');

        const versions = await h.mgmt('GET', `/actions/actions/${action.id}/versions`);
        expect(versions.status).toBe(200);
        expect(versions.body).toEqual(envelope('versions', [expect.any(Object), expect.any(Object)]));
        expect(versions.body.versions.map((v: { number: number }) => v.number)).toEqual([2, 1]);
        expect(versions.body.versions.map((v: { deployed: boolean }) => v.deployed)).toEqual([true, false]);
        expect(versions.body.versions[0]).toEqual(res.body);
        expect(JSON.stringify(versions.body)).not.toContain('shh-secret');

        const got = await h.mgmt('GET', `/actions/actions/${action.id}`);
        expect(got.body.deployed_version.number).toBe(2);
        expect(got.body.all_changes_deployed).toBe(true);

        const v1 = versions.body.versions[1];
        const single = await h.mgmt('GET', `/actions/actions/${action.id}/versions/${v1.id}`);
        expect(single.status).toBe(200);
        expect(single.body).toEqual(v1);
        const paged = await h.mgmt('GET', `/actions/actions/${action.id}/versions?per_page=1`);
        expect(paged.body).toMatchObject({ total: 2, per_page: 1, page: 0, start: 0, limit: 1, length: 1 });
        expect(paged.body.versions[0].number).toBe(2);
        expect((await h.mgmt('GET', `/actions/actions/${action.id}/versions/nope`)).status).toBe(404);
        expect((await h.mgmt('GET', '/actions/actions/nope/versions')).status).toBe(404);
        expect((await h.mgmt('GET', `/actions/actions/${minimal.id}/versions`)).body).toEqual(envelope('versions', []));
    });

    it('redeploying an old version republishes it as a new version', async () => {
        const versions = (await h.mgmt('GET', `/actions/actions/${action.id}/versions`)).body.versions;
        const v1 = versions.find((v: { number: number }) => v.number === 1);
        const res = await h.mgmt('POST', `/actions/actions/${action.id}/versions/${v1.id}/deploy`);
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ number: 3, deployed: true, code: CODE_V1 });
        const got = await h.mgmt('GET', `/actions/actions/${action.id}`);
        expect(got.body.code).toBe(CODE_V1);
        expect(got.body.deployed_version.number).toBe(3);
        expect(got.body.all_changes_deployed).toBe(true);
        expect((await h.mgmt('GET', `/actions/actions/${action.id}/versions`)).body.total).toBe(3);
        expect((await h.mgmt('POST', `/actions/actions/${action.id}/versions/nope/deploy`)).status).toBe(404);
    });

    it('GET /actions/triggers lists post-login v3', async () => {
        const res = await h.mgmt('GET', '/actions/triggers');
        expect(res.status).toBe(200);
        expect(Object.keys(res.body)).toEqual(['triggers']);
        expect(res.body.triggers).toContainEqual({
            id: 'post-login',
            version: 'v3',
            status: 'CURRENT',
            runtimes: ['node18', 'node22'],
            default_runtime: 'node22',
        });
        expect(res.body.triggers).toContainEqual(
            expect.objectContaining({ id: 'post-login', version: 'v2', status: 'DEPRECATED' })
        );
        expect(res.body.triggers.map((t: { id: string }) => t.id)).toEqual(
            expect.arrayContaining(['credentials-exchange', 'pre-user-registration', 'post-user-registration'])
        );
        expect((await h.mgmt('GET', '/actions/status')).body).toEqual({ status: 'active' });
    });

    it('PATCH bindings binds deployed actions and GET returns the envelope', async () => {
        const path = '/actions/triggers/post-login/bindings';
        const empty = await h.mgmt('GET', path);
        expect(empty.status).toBe(200);
        expect(empty.body).toEqual(envelope('bindings', []));

        const res = await h.mgmt('PATCH', path, {
            bindings: [{ ref: { type: 'action_id', value: action.id }, display_name: 'Add claims binding' }],
        });
        expect(res.status).toBe(200);
        expect(res.body).toEqual({
            bindings: [
                {
                    id: uuid(),
                    trigger_id: 'post-login',
                    action: expect.objectContaining({
                        id: action.id,
                        name: 'Add claims v2',
                        supported_triggers: POST_LOGIN,
                    }),
                    display_name: 'Add claims binding',
                    created_at: iso(),
                    updated_at: iso(),
                },
            ],
        });
        const binding = res.body.bindings[0];
        for (const hidden of ['code', 'secrets', 'deployed_version', 'current_version']) {
            expect(binding.action, hidden).not.toHaveProperty(hidden);
        }

        const list = await h.mgmt('GET', path);
        expect(list.body).toEqual(envelope('bindings', [binding]));
        expect(list.body).toMatchObject({ start: 0, limit: 20, total: 1 });

        // Re-binding by name keeps the binding id and created_at; display_name defaults to the action name.
        const again = await h.mgmt('PATCH', path, {
            bindings: [{ ref: { type: 'action_name', value: 'Add claims v2' } }],
        });
        expect(again.status).toBe(200);
        expect(again.body.bindings).toHaveLength(1);
        expect(again.body.bindings[0]).toMatchObject({
            id: binding.id,
            created_at: binding.created_at,
            display_name: 'Add claims v2',
        });

        expect((await h.mgmt('PATCH', path, { bindings: [] })).body).toEqual({ bindings: [] });
        expect((await h.mgmt('GET', path)).body).toEqual(envelope('bindings', []));

        const restored = await h.mgmt('PATCH', path, {
            bindings: [{ ref: { type: 'action_id', value: action.id }, display_name: 'Add claims binding' }],
        });
        expect(restored.status).toBe(200);
        expect(restored.body.bindings[0].id).not.toBe(binding.id);
    });

    it('rejects invalid bindings and unknown triggers', async () => {
        const undeployed = await h.mgmt('PATCH', '/actions/triggers/credentials-exchange/bindings', {
            bindings: [{ ref: { type: 'action_id', value: minimal.id } }],
        });
        expect(undeployed.status).toBe(400);
        expect(undeployed.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Action 'Minimal' must be deployed before it can be bound",
            errorCode: 'action_not_deployed',
        });

        const unsupported = await h.mgmt('PATCH', '/actions/triggers/credentials-exchange/bindings', {
            bindings: [{ ref: { type: 'action_id', value: action.id } }],
        });
        expect(unsupported.status).toBe(400);
        expect(unsupported.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Action 'Add claims v2' does not support trigger 'credentials-exchange'",
            errorCode: 'invalid_trigger',
        });

        const unknownAction = await h.mgmt('PATCH', '/actions/triggers/post-login/bindings', {
            bindings: [{ ref: { type: 'action_id', value: 'nope' } }],
        });
        expect(unknownAction.status).toBe(400);
        expect(unknownAction.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Action 'nope' does not exist",
            errorCode: 'inexistent_action',
        });

        const unknownTrigger = await h.mgmt('PATCH', '/actions/triggers/nope/bindings', { bindings: [] });
        expect(unknownTrigger.status).toBe(404);
        expect(unknownTrigger.body).toEqual({
            statusCode: 404,
            error: 'Not Found',
            message: "Unknown trigger 'nope'",
            errorCode: 'invalid_trigger',
        });
        const unknownTriggerGet = await h.mgmt('GET', '/actions/triggers/nope/bindings');
        expect(unknownTriggerGet.status).toBe(404);
        expect(unknownTriggerGet.body).toEqual(unknownTrigger.body);

        const notArray = await h.mgmt('PATCH', '/actions/triggers/post-login/bindings', { bindings: 'x' });
        expect(notArray.status).toBe(400);
        expect(notArray.body.message).toBe("Payload validation error: 'bindings' must be an array");
        const noRef = await h.mgmt('PATCH', '/actions/triggers/post-login/bindings', {
            bindings: [{ display_name: 'x' }],
        });
        expect(noRef.status).toBe(400);
        expect(noRef.body.message).toBe("Payload validation error: every binding requires 'ref.type' and 'ref.value'");

        // Failed requests leave the existing bindings untouched.
        expect((await h.mgmt('GET', '/actions/triggers/post-login/bindings')).body.total).toBe(1);
        expect((await h.mgmt('GET', '/actions/triggers/credentials-exchange/bindings')).body.total).toBe(0);
    });

    it('DELETE refuses a bound action unless force=true, then removes its binding', async () => {
        const refused = await h.mgmt('DELETE', `/actions/actions/${action.id}`);
        expect(refused.status).toBe(400);
        expect(refused.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: 'The action is bound to a trigger; unbind it or use force=true',
            errorCode: 'action_bound',
        });
        expect((await h.mgmt('GET', `/actions/actions/${action.id}`)).status).toBe(200);
        expect((await h.mgmt('DELETE', `/actions/actions/${action.id}?force=false`)).status).toBe(400);

        const forced = await h.mgmt('DELETE', `/actions/actions/${action.id}?force=true`);
        expect(forced.status).toBe(204);
        expect(forced.body).toBeUndefined();
        expect((await h.mgmt('GET', `/actions/actions/${action.id}`)).status).toBe(404);
        expect((await h.mgmt('GET', `/actions/actions/${action.id}/versions`)).status).toBe(404);
        expect((await h.mgmt('GET', '/actions/triggers/post-login/bindings')).body).toEqual(envelope('bindings', []));

        // Unbound and unknown actions delete with a plain 204.
        expect((await h.mgmt('DELETE', `/actions/actions/${minimal.id}`)).status).toBe(204);
        expect((await h.mgmt('DELETE', '/actions/actions/nope')).status).toBe(204);
        expect((await h.mgmt('GET', '/actions/actions')).body).toEqual(envelope('actions', []));
    });
});
