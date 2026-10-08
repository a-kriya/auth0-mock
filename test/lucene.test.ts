import { describe, expect, it } from 'vitest';
import { QuerySyntaxError, compileQuery, parseQuery } from '../src/lucene.ts';

const alice = {
    user_id: 'auth0|alice',
    email: 'alice@example.com',
    name: 'Alice Example',
    nickname: 'alice',
    logins_count: 3,
    created_at: '2024-03-15T10:00:00.000Z',
    app_metadata: {
        type: 'internal',
        institutionIds: ['A', 'B'],
        roles: [{ name: 'Admin' }, { name: 'Reader' }],
    },
};
const bob = {
    user_id: 'auth0|bob',
    email: 'bob@example.com',
    name: 'Bob Example',
    nickname: 'bob',
    blocked: true,
    logins_count: 10,
    created_at: '2023-01-01T00:00:00.000Z',
    app_metadata: { type: 'external', institutionIds: ['C'], roles: [{ name: 'Reader' }] },
};
const john = {
    user_id: 'auth0|john',
    email: 'john.doe@example.com',
    name: 'John Doe',
    logins_count: 0,
    created_at: '2025-06-01T12:00:00.000Z',
};
const users = [alice, bob, john];

/** user_ids of the fixture users matched by `query`. */
const matching = (query: string): string[] => users.filter(compileQuery(query)).map((u) => u.user_id);

describe('parseQuery', () => {
    it('returns the `all` node for an empty or blank query', () => {
        expect(parseQuery('')).toEqual({ type: 'all' });
        expect(parseQuery('   ')).toEqual({ type: 'all' });
    });

    it('parses a field term', () => {
        expect(parseQuery('email:alice')).toEqual({ type: 'term', field: 'email', text: 'alice', phrase: false });
        expect(parseQuery('name:"Alice Example"')).toEqual({
            type: 'term',
            field: 'name',
            text: 'Alice Example',
            phrase: true,
        });
    });

    it('parses boolean operators with AND binding tighter than OR', () => {
        expect(parseQuery('a OR b AND c')).toEqual({
            type: 'or',
            children: [
                { type: 'term', field: undefined, text: 'a', phrase: false },
                {
                    type: 'and',
                    children: [
                        { type: 'term', field: undefined, text: 'b', phrase: false },
                        { type: 'term', field: undefined, text: 'c', phrase: false },
                    ],
                },
            ],
        });
    });

    it('parses negation in its three spellings', () => {
        const expected = {
            type: 'not',
            child: { type: 'term', field: 'blocked', text: 'true', phrase: false },
        };
        expect(parseQuery('!blocked:true')).toEqual(expected);
        expect(parseQuery('-blocked:true')).toEqual(expected);
        expect(parseQuery('NOT blocked:true')).toEqual(expected);
    });

    it('parses ranges with inclusive and exclusive bounds', () => {
        expect(parseQuery('logins_count:[1 TO 5]')).toEqual({
            type: 'range',
            field: 'logins_count',
            lower: '1',
            upper: '5',
            includeLower: true,
            includeUpper: true,
        });
        expect(parseQuery('logins_count:{1 TO 5]')).toMatchObject({ includeLower: false, includeUpper: true });
        expect(parseQuery('logins_count:[* TO 5}')).toMatchObject({ lower: '*', includeUpper: false });
    });

    it('parses existence checks', () => {
        expect(parseQuery('_exists_:app_metadata.type')).toEqual({ type: 'exists', field: 'app_metadata.type' });
        expect(parseQuery('app_metadata.type:*')).toEqual({ type: 'exists', field: 'app_metadata.type' });
    });

    it('distributes a grouped value list over the field', () => {
        expect(parseQuery('nickname:(alice bob)')).toEqual({
            type: 'or',
            children: [
                { type: 'term', field: 'nickname', text: 'alice', phrase: false },
                { type: 'term', field: 'nickname', text: 'bob', phrase: false },
            ],
        });
    });
});

describe('compileQuery', () => {
    it('matches field:value', () => {
        expect(matching('email:alice@example.com')).toEqual(['auth0|alice']);
        expect(matching('nickname:bob')).toEqual(['auth0|bob']);
        expect(matching('email:nobody@example.com')).toEqual([]);
    });

    it('matches a quoted phrase against the whole value', () => {
        expect(matching('name:"Alice Example"')).toEqual(['auth0|alice']);
        expect(matching('name:"alice example"')).toEqual(['auth0|alice']);
        expect(matching('name:"Alice"')).toEqual([]);
    });

    it('treats field:(a b) as OR', () => {
        expect(matching('nickname:(alice bob)')).toEqual(['auth0|alice', 'auth0|bob']);
        expect(matching('nickname:(alice OR bob)')).toEqual(['auth0|alice', 'auth0|bob']);
        expect(matching('nickname:(alice AND bob)')).toEqual([]);
    });

    it('honours parentheses: (a OR b) AND c', () => {
        expect(matching('(email:alice@example.com OR email:bob@example.com) AND blocked:true')).toEqual(['auth0|bob']);
        expect(matching('(email:alice@example.com OR email:bob@example.com) AND logins_count:3')).toEqual([
            'auth0|alice',
        ]);
    });

    it('uses OR between adjacent clauses', () => {
        expect(matching('email:alice@example.com email:john.doe@example.com')).toEqual(['auth0|alice', 'auth0|john']);
    });

    it('accepts && and || as operator aliases and ignores a leading +', () => {
        expect(matching('email:alice@example.com || email:bob@example.com')).toEqual(['auth0|alice', 'auth0|bob']);
        expect(matching('nickname:alice && blocked:true')).toEqual([]);
        expect(matching('+nickname:alice')).toEqual(['auth0|alice']);
    });

    it('!blocked:true matches when blocked is absent and rejects blocked: true', () => {
        expect(matching('blocked:true')).toEqual(['auth0|bob']);
        expect(matching('!blocked:true')).toEqual(['auth0|alice', 'auth0|john']);
        expect(compileQuery('!blocked:true')({ blocked: false })).toBe(true);
        expect(compileQuery('!blocked:true')({ blocked: true })).toBe(false);
        expect(compileQuery('!blocked:true')({})).toBe(true);
    });

    it('supports -field:value and NOT', () => {
        expect(matching('-blocked:true')).toEqual(['auth0|alice', 'auth0|john']);
        expect(matching('NOT blocked:true')).toEqual(['auth0|alice', 'auth0|john']);
        expect(matching('NOT nickname:alice AND NOT nickname:bob')).toEqual(['auth0|john']);
        // A hyphen inside a word is literal, not negation.
        expect(compileQuery('name:foo-bar')({ name: 'foo-bar' })).toBe(true);
    });

    it('supports * and ? wildcards', () => {
        expect(matching('email:(*john*)')).toEqual(['auth0|john']);
        expect(matching('email:*@example.com')).toEqual(['auth0|alice', 'auth0|bob', 'auth0|john']);
        expect(matching('nickname:?ob')).toEqual(['auth0|bob']);
        expect(matching('nickname:b?b')).toEqual(['auth0|bob']);
        expect(matching('nickname:?lice')).toEqual(['auth0|alice']);
        expect(matching('nickname:?ob?')).toEqual([]);
    });

    it('unescapes backslash sequences and treats the escaped character literally', () => {
        expect(matching(String.raw`email:(john\.doe\@example\.com)`)).toEqual(['auth0|john']);
        const impostor = { email: 'johnxdoe@example.com' };
        expect(compileQuery(String.raw`email:john\.doe@example.com`)(impostor)).toBe(false);
        expect(compileQuery('email:john?doe@example.com')(impostor)).toBe(true);
        expect(compileQuery(String.raw`name:a\*b`)({ name: 'a*b' })).toBe(true);
        expect(compileQuery(String.raw`name:a\*b`)({ name: 'aXb' })).toBe(false);
    });

    it('matches numeric ranges', () => {
        expect(matching('logins_count:[1 TO 5]')).toEqual(['auth0|alice']);
        expect(matching('logins_count:[3 TO 10]')).toEqual(['auth0|alice', 'auth0|bob']);
        expect(matching('logins_count:{3 TO 10}')).toEqual([]);
        expect(matching('logins_count:{0 TO 10}')).toEqual(['auth0|alice']);
        expect(matching('logins_count:[* TO 5]')).toEqual(['auth0|alice', 'auth0|john']);
        expect(matching('logins_count:[10 TO *]')).toEqual(['auth0|bob']);
        expect(matching('logins_count:[* TO *]')).toEqual(['auth0|alice', 'auth0|bob', 'auth0|john']);
        // Numeric, not lexicographic: 10 > 5.
        expect(compileQuery('logins_count:[5 TO 20]')({ logins_count: 10 })).toBe(true);
    });

    it('matches string and date ranges on created_at', () => {
        expect(matching('created_at:[2024-01-01 TO 2024-12-31]')).toEqual(['auth0|alice']);
        expect(matching('created_at:["2023-01-01T00:00:00.000Z" TO "2024-12-31T23:59:59.999Z"]')).toEqual([
            'auth0|alice',
            'auth0|bob',
        ]);
        expect(matching('created_at:{"2023-01-01T00:00:00.000Z" TO *}')).toEqual(['auth0|alice', 'auth0|john']);
        expect(matching('created_at:[* TO 2023-12-31]')).toEqual(['auth0|bob']);
    });

    it('supports _exists_:field and field:*', () => {
        expect(matching('_exists_:app_metadata.type')).toEqual(['auth0|alice', 'auth0|bob']);
        expect(matching('app_metadata.type:*')).toEqual(['auth0|alice', 'auth0|bob']);
        expect(matching('_exists_:blocked')).toEqual(['auth0|bob']);
        expect(matching('blocked:*')).toEqual(['auth0|bob']);
        expect(matching('NOT _exists_:app_metadata')).toEqual(['auth0|john']);
        expect(compileQuery('_exists_:nickname')({ nickname: null })).toBe(false);
    });

    it('keyword fields are case-sensitive, analysed fields are case-insensitive', () => {
        expect(matching('app_metadata.type:Internal')).toEqual([]);
        expect(matching('app_metadata.type:internal')).toEqual(['auth0|alice']);
        expect(matching('user_id:auth0|alice')).toEqual(['auth0|alice']);
        expect(matching('user_id:AUTH0|ALICE')).toEqual([]);
        expect(matching('email:ALICE@EXAMPLE.COM')).toEqual(['auth0|alice']);
        expect(matching('name:alice*')).toEqual(['auth0|alice']);
        expect(matching('name:"BOB EXAMPLE"')).toEqual(['auth0|bob']);
        expect(matching('app_metadata.institutionIds:"a"')).toEqual([]);
    });

    it('matches when any array element matches (array-any semantics)', () => {
        expect(matching('app_metadata.institutionIds:("A" "B")')).toEqual(['auth0|alice']);
        expect(matching('app_metadata.institutionIds:("B")')).toEqual(['auth0|alice']);
        expect(matching('app_metadata.institutionIds:("C" "Z")')).toEqual(['auth0|bob']);
        expect(matching('app_metadata.institutionIds:("Z")')).toEqual([]);
        expect(matching('app_metadata.roles.name:("Admin")')).toEqual(['auth0|alice']);
        expect(matching('app_metadata.roles.name:("Reader")')).toEqual(['auth0|alice', 'auth0|bob']);
        expect(matching('app_metadata.roles.name:Admin')).toEqual(['auth0|alice']);
    });

    it('a bare term matches email, name or user_id', () => {
        expect(matching('alice@example.com')).toEqual(['auth0|alice']);
        expect(matching('"Bob Example"')).toEqual(['auth0|bob']);
        expect(matching('auth0|john')).toEqual(['auth0|john']);
        expect(matching('*doe*')).toEqual(['auth0|john']);
        expect(matching('alice')).toEqual(['auth0|alice']);
        expect(matching('nobody')).toEqual([]);
    });

    it('an empty query matches everything', () => {
        expect(matching('')).toEqual(['auth0|alice', 'auth0|bob', 'auth0|john']);
        expect(matching('   ')).toEqual(['auth0|alice', 'auth0|bob', 'auth0|john']);
    });

    it('throws QuerySyntaxError on malformed input', () => {
        const malformed = [
            'email:"alice',
            '(email:alice',
            'email:alice)',
            'email:',
            'email:(alice',
            'logins_count:[1 TO',
            'logins_count:[1 TO 5',
            'logins_count:[1 5]',
            'AND',
            'email:alice AND',
            '_exists_:',
        ];
        for (const query of malformed) {
            expect(() => compileQuery(query), query).toThrow(QuerySyntaxError);
            expect(() => parseQuery(query), query).toThrow(QuerySyntaxError);
        }
        try {
            parseQuery('email:"alice');
        } catch (error) {
            expect(error).toBeInstanceOf(QuerySyntaxError);
            expect((error as Error).name).toBe('QuerySyntaxError');
            expect((error as Error).message).toMatch(/Unterminated quoted string/);
        }
        expect(() => parseQuery('email:')).toThrow(/Expected a value for field 'email'/);
    });

    it('evaluates a composite query taken from a real application', () => {
        const query = String.raw`!blocked:true AND app_metadata.type:internal AND (user_id:(x\_y) OR email:(*x\_y*) OR name:(*x\_y*) OR app_metadata.institutionIds:("X\_Y"))`;
        const predicate = compileQuery(query);

        const byEmail = {
            user_id: 'auth0|m1',
            email: 'x_y@example.com',
            name: 'M One',
            app_metadata: { type: 'internal', institutionIds: [] },
        };
        const byInstitution = {
            user_id: 'auth0|m2',
            email: 'm2@example.com',
            name: 'M Two',
            app_metadata: { type: 'internal', institutionIds: ['Q', 'X_Y'] },
        };
        const byName = {
            user_id: 'auth0|m3',
            email: 'm3@example.com',
            name: 'Dr x_y Smith',
            app_metadata: { type: 'internal' },
        };
        const byUserId = { user_id: 'x_y', email: 'other@example.com', app_metadata: { type: 'internal' } };
        const explicitlyUnblocked = {
            user_id: 'auth0|m4',
            email: 'x_y@example.com',
            blocked: false,
            app_metadata: { type: 'internal' },
        };
        for (const user of [byEmail, byInstitution, byName, byUserId, explicitlyUnblocked]) {
            expect(predicate(user), user.user_id).toBe(true);
        }

        const blocked = {
            user_id: 'auth0|r1',
            email: 'x_y@example.com',
            blocked: true,
            app_metadata: { type: 'internal' },
        };
        const external = {
            user_id: 'auth0|r2',
            email: 'x_y@example.com',
            app_metadata: { type: 'external', institutionIds: ['X_Y'] },
        };
        const capitalisedType = {
            user_id: 'auth0|r3',
            email: 'x_y@example.com',
            app_metadata: { type: 'Internal' },
        };
        const noSearchHit = {
            user_id: 'auth0|r4',
            email: 'zzz@example.com',
            name: 'Zed',
            app_metadata: { type: 'internal', institutionIds: ['X_Z'] },
        };
        const lowerCaseInstitution = {
            user_id: 'auth0|r5',
            email: 'zzz@example.com',
            app_metadata: { type: 'internal', institutionIds: ['x_y'] },
        };
        const prefixedUserId = { user_id: 'auth0|x_y', email: 'zzz@example.com', app_metadata: { type: 'internal' } };
        const noMetadata = { user_id: 'auth0|r6', email: 'x_y@example.com' };
        for (const user of [
            blocked,
            external,
            capitalisedType,
            noSearchHit,
            lowerCaseInstitution,
            prefixedUserId,
            noMetadata,
        ]) {
            expect(predicate(user), user.user_id).toBe(false);
        }
    });
});
