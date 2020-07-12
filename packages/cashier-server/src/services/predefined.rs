#[derive(Debug)]
pub struct PredefinedPermission(
    pub &'static str, // subject
    pub &'static str, // action
    pub &'static str, // displayName
    pub &'static str, // description
);

#[derive(Debug)]
pub struct PredefinedRole(
    pub &'static str, // name
    pub &'static [(&'static str /* subject */, &'static str /* action */)], // permissions
    pub &'static str, // displayName
    pub &'static str, // description
    pub bool, // whether is acquired by newly registered users
);

// There exists two special id: default and me. Default is for users who are not logged-in.
// Me is for user to get own information.
pub const PREDEFINED_PERMISSIONS: &[PredefinedPermission] = &[
    // CRUD for permissions
    PredefinedPermission("permission", "read", "Read Permission", "Read the information of a permission via GET /api/permissions/:id"),
    PredefinedPermission("permission", "list", "List Permission", "List all the permissions matching criteria via GET /api/permissions"),
    PredefinedPermission("permission", "update", "Update Permission", "Update the information of a permission via PATCH /api/permissions/:id"),
    // CRUD for roles
    PredefinedPermission("role", "create", "Create Role", "Create a new role via POST /api/roles"),
    PredefinedPermission("role", "read", "Read Role", "Read the information of a role via GET /api/roles/:id"),
    PredefinedPermission("role", "list", "List Role", "List all the roles matching criteria via GET /api/roles"),
    PredefinedPermission("role", "update", "Update Role", "Update the information of a role via PATCH /api/roles/:id"),
    PredefinedPermission("role", "delete", "Delete Role", "Delete a role via DELETE /api/roles/:id"),
    // CRUD for role's permissions
    PredefinedPermission("role-permission", "update", "Update Role's Permission", "Update role's permission via POST /api/roles/:id/permissions"),
    // Subjects for role's permissions
    PredefinedPermission("role-permission-updated", "subscribe", "Subscribe Role-Permission-Updated", "Subscribe to role's permission updated message"),
    // CRUD for users
    PredefinedPermission("user", "create", "Create User", "Create a new user via POST /api/users"),
    PredefinedPermission("user", "read", "Read User", "Read the information of a user via GET /api/users/:id"),
    PredefinedPermission("user", "read-self", "Read Self User", "Read user's own information via GET /api/users/me"),
    PredefinedPermission("user", "list", "List User", "List all the users matching criteria via GET /api/users"),
    PredefinedPermission("user", "update", "Update User", "Update the information of a user via PATCH /api/users/:id"),
    PredefinedPermission("user", "update-self", "Update Self User", "Update user's own information via PATCH /api/users/me"),
    PredefinedPermission("user", "delete", "Delete User", "Delete a user via DELETE /api/users/:id"),
    PredefinedPermission("user", "delete-self", "Delete Self User", "Delete user's own account via DELETE /api/users/me"),
    // CRUD for user's public information
    PredefinedPermission("user-public", "read", "Read User Public", "Read the public information of a user via GET /api/users/:id?populate=public"),
    PredefinedPermission("user-public", "list", "List User Public", "List all the users matching criteria with public information via GET /api/users?populate=public"),
    // CRUD for user's password
    PredefinedPermission("user-password", "update", "Update Self User Password", "Update user's password via POST /api/users/:id/password"),
    PredefinedPermission("user-password", "update-self", "Update Self User Password", "Update user's password via POST /api/users/me/password"),
    // CRUD for user's avatar
    PredefinedPermission("user-avatar", "update", "Update Self User Avatar", "Update user's avatar via POST /api/users/:id/avatar"),
    PredefinedPermission("user-avatar", "delete", "Delete Self User Avatar", "Delete user's avatar via DELETE /api/users/:id/avatar"),
    PredefinedPermission("user-avatar", "update-self", "Update Self User Avatar", "Update user's avatar via POST /api/users/me/avatar"),
    PredefinedPermission("user-avatar", "delete-self", "Delete Self User Avatar", "Delete user's avatar via DELETE /api/users/me/avatar"),
    // CRUD for user's role
    PredefinedPermission("user-role", "update", "Update User's Role", "Update user's roles via POST /api/users/:id/roles"),
    // Subjects for user's roles
    PredefinedPermission("user-role-updated", "subscribe", "Subscribe User-Role-Updated", "Subscribe to user's role updated message"),
    // Subjects for token
    PredefinedPermission("user-created", "subscribe", "Subscribe User-Created", "Subscribe to user created message"),
    PredefinedPermission("user-updated", "subscribe", "Subscribe User-Updated", "Subscribe to user updated message"),
    PredefinedPermission("user-deleted", "subscribe", "Subscribe User-Deleted", "Subscribe to user deleted message"),
    PredefinedPermission("user-updated-self", "subscribe", "Subscribe Self User-Updated", "Subscribe to self user updated message"),
    PredefinedPermission("user-deleted-self", "subscribe", "Subscribe Self User-Deleted", "Subscribe to self user deleted message"),
    // CRUD for token
    PredefinedPermission("token", "acquire-by-username", "Acquire Token By Username", "Acquire token by username via POST /api/tokens/acquire-by-username"),
    PredefinedPermission("token", "acquire-by-email", "Acquire Token By Email", "Acquire token by email via POST /api/tokens/acquire-by-email"),
    PredefinedPermission("token", "resume", "Resume Token", "Resume a token by providing a valid token via POST /api/tokens/resume"),
    PredefinedPermission("token", "revoke", "Revoke Token", "Revoke all the tokens belong to a user via DELETE /api/tokens/users/:uid"),
    PredefinedPermission("token", "revoke-self", "Revoke Self Token", "Revoke all user's own tokens via DELETE /api/tokens/users/me"),
    PredefinedPermission("token", "list", "List Token", "List all the tokens belong to a user via GET /api/tokens/users/:uid"),
    PredefinedPermission("token", "list-self", "List Self Token", "List all user's own tokens tokens via GET /api/tokens/users/me"),
    PredefinedPermission("token", "read-single", "Read Single Token", "Read the information of a token via GET /api/tokens/jwt/:jti"),
    PredefinedPermission("token", "revoke-single", "Revoke Single Token", "Revoke one token belong to a user via DELETE /api/tokens/jwt/:jti"),
    PredefinedPermission("token", "read-single-self", "Read Single Self Token", "Read the information of a token via GET /api/tokens/my-jwt/:jti"),
    PredefinedPermission("token", "revoke-single-self", "Revoke Single Self Token", "Revoke user's own token via DELETE /api/tokens/my-jwt/:jti"),
    // Subjects for token
    PredefinedPermission("token-acquired", "subscribe", "Subscribe Token-Acquired", "Subscribe token acquired message"),
    PredefinedPermission("token-revoked", "subscribe", "Subscribe Token-Revoked", "Subscribe token revoked message"),
    PredefinedPermission("token-acquired-self", "subscribe", "Subscribe Self Token-Acquired", "Subscribe self token acquired message"),
    PredefinedPermission("token-revoked-self", "subscribe", "Subscribe Self Token-Revoked", "Subscribe self token revoked message"),
    // User registration
    PredefinedPermission("registration", "create", "Register User", "Register a new user via POST /api/registrations"),
    PredefinedPermission("registration", "read", "Query User Registration", "Query a user registration status via GET /api/registrations/{reg_id}"),
    PredefinedPermission("registration", "confirm", "Confirm User Registration", "Confirm a user registration via POST /api/registrations/{reg_id}/confirm"),
    PredefinedPermission("registration", "resend", "Resend User Registration E-mail", "Resend user registration email via POST /api/registrations/{reg_id}/resend"),
    PredefinedPermission("user-username", "check-existence", "Check Username Existence", "Check whether username is occupied via GET /api/users/check-username-existence"),
    PredefinedPermission("user-email", "check-existence", "Check E-mail Existence", "Check whether E-mail is occupied via POST /api/users/check-email-existence"),
    // User email updating
    PredefinedPermission("user-email-updating", "create-self", "Update Self Email", "Update self's email via POST /api/email-updating/"),
    PredefinedPermission("user-email-updating", "read", "Read User Updating Email", "Query user's email updating via POST /api/email-updating/{update_id}"),
    PredefinedPermission("user-email-updating", "read-self", "Read Self Updating Email", "Query self's email updating via POST /api/email-updating/{update_id}"),
    PredefinedPermission("user-email-updating", "confirm", "Confirm User Updating Email", "Confirm user's email updating via POST /api/email-updating/{update_id}/confirm"),
    PredefinedPermission("user-email-updating", "confirm-self", "Confirm Self Updating Email", "Confirm self's email updating via POST /api/email-updating/{update_id}/confirm"),
    PredefinedPermission("user-email-updating", "resend", "Resend User Updating Email", "Resend user's email updating via POST /api/email-updating/{update_id}/resend"),
    PredefinedPermission("user-email-updating", "resend-self", "Resend Self Updating Email", "Resend self's email updating via POST /api/email-updating/{update_id}/resend"),
];

pub const PREDEFINED_ROLES: &[PredefinedRole] = &[
    PredefinedRole("permission-admin", &[
        ("permission", "read"),
        ("permission", "list"),
        ("permission", "update"),
        ("role", "create"),
        ("role", "read"),
        ("role", "list"),
        ("role", "update"),
        ("role", "delete"),
    ], "Administrator for Permissions", "Manage permissions and roles", false),
    PredefinedRole("user-admin", &[
        ("permission", "read"),
        ("permission", "list"),
        ("role", "read"),
        ("role", "list"),
        ("user", "create"),
        ("user", "read"),
        ("user", "list"),
        ("user", "update"),
        ("user", "delete"),
        ("user-password", "update"),
        ("user-avatar", "update"),
        ("user-avatar", "delete"),
        ("token", "revoke"),
        ("token", "revoke-single"),
        ("token-acquired", "subscribe"),
        ("token-revoked", "subscribe"),
        ("user-created", "subscribe"),
        ("user-updated", "subscribe"),
        ("user-deleted", "subscribe"),
        ("user-email-updating", "read"),
        ("user-email-updating", "confirm"),
        ("user-email-updating", "resend"),
    ], "Administrator for Users", "Manage users", false),
    PredefinedRole("normal-user", &[
        ("user", "read-self"),
        ("user", "update-self"),
        ("user-public", "read"),
        ("user-public", "list"),
        ("user-password", "update-self"),
        ("user-avatar", "update-self"),
        ("user-avatar", "delete-self"),
        ("token", "resume"),
        ("token", "revoke-self"),
        ("token", "revoke-single-self"),
        ("token", "list-self"),
        ("token", "read-single-self"),
        ("user-updated-self", "subscribe"),
        ("user-deleted-self", "subscribe"),
        ("token-acquired-self", "subscribe"),
        ("token-revoked-self", "subscribe"),
        ("user-email-updating", "create-self"),
        ("user-email-updating", "read-self"),
        ("user-email-updating", "confirm-self"),
        ("user-email-updating", "resend-self"),
    ], "Normal User", "Manage users's own information", true),
    PredefinedRole("default", &[
        ("registration", "create"),
        ("registration", "confirm"),
        ("registration", "read"),
        ("registration", "resend"),
        ("token", "acquire-by-username"),
        ("token", "acquire-by-email"),
        ("user-username", "check-existence"),
        ("user-email", "check-existence"),
    ], "Default", "Every user including not logged-in ones implicitly has this role", false),
];

pub const SUPERUSER_ROLES: &[&str] = &[
    "permission-admin",
    "user-admin",
    "normal-user",
];
