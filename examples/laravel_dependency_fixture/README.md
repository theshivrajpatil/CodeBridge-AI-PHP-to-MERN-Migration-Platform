# Laravel-shaped dependency analysis fixture

This is a small, inert PHP source fixture for testing CodeBridge's static
analysis. It is not a complete Laravel application and must not be treated as
runnable. It contains a grouped route, controller, service, and model reference.

Scan this folder in CodeBridge to check route/group extraction and backend
source-reference reporting. Expected static evidence includes:

- `GET /admin/users` with `auth` inherited from the literal route group;
- `UserController` route action `index`;
- `UserController.php` constructing and calling `UserService`;
- `UserService.php` referencing `User` and Eloquent-style query/create calls.

All findings remain static evidence requiring review. No PHP is executed and no
database is contacted.
