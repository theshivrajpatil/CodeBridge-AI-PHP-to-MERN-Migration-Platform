# Migration report — blog

Source fingerprint: `1c176dd1cb690861518e2f706712b4243b85a513f241b570efaaa44b6e650228`

## Endpoint plan
| Method | Path | Action | Reason |
|---|---|---|---|
| GET | `/api/admin/stats` | IMPLEMENT | recognised recipe |
| DELETE | `/api/comments/{comment}` | IMPLEMENT | recognised recipe |
| GET | `/api/health` | IMPLEMENT | literal JSON closure |
| POST | `/api/login` | IMPLEMENT | recognised recipe |
| POST | `/api/logout` | IMPLEMENT | recognised recipe |
| GET | `/api/posts` | IMPLEMENT | recognised recipe |
| POST | `/api/posts` | IMPLEMENT | recognised recipe |
| DELETE | `/api/posts/{post}` | IMPLEMENT | recognised recipe |
| GET | `/api/posts/{post}` | IMPLEMENT | recognised recipe |
| PATCH | `/api/posts/{post}` | IMPLEMENT | recognised recipe |
| PUT | `/api/posts/{post}` | IMPLEMENT | recognised recipe |
| GET | `/api/posts/{post}/comments` | IMPLEMENT | recognised recipe |
| POST | `/api/posts/{post}/comments` | STUB | authorization rule for 'create' is unresolved (Laravel denies by default) |
| POST | `/api/register` | IMPLEMENT | recognised recipe |

## Security findings carried over from analysis
* `5d841a7f7df5a513` AUTHORIZATION_RULE_UNRESOLVED (MEDIUM)
* `2f889e03a78ea768` CREDENTIAL_ENDPOINT_WITHOUT_RATE_LIMIT (MEDIUM)

## Parity
Static parity of the generated server against the PHP contracts: equivalent 13, mismatch 0, partial 0, not implemented 1, unverified 0 of 14. This is structural evidence, not proof of equivalence.

## Intentional divergences
* Primary keys become MongoDB ObjectIds (24-hex strings) instead of auto-increment integers; clients must not assume numeric ids.
* Timestamps serialise as ISO-8601 with millisecond precision (Laravel emits microseconds).
* Sanctum tokens become signed JWTs backed by a revocable AccessToken collection (logout revokes server-side).
* 422 bodies use the generic message 'The given data was invalid.' (Laravel builds the message from the first rule failure).
* Existing bcrypt password hashes remain verifiable (bcryptjs accepts $2y$), allowing user migration without password resets.
* Authorization is deny-by-default; rules that could not be translated deterministically are stubbed, not guessed.

## Notes requiring review
* none
