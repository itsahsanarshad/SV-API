create extension if not exists "pgcrypto";

CREATE table users_roles_assignment (
    user_role_assignment_id uuid NOT NULL DEFAULT gen_random_uuid(),
    user_uuid uuid NOT NULL,
    role_id uuid NOT NULL,
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_role_assignment_id),
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid),
    FOREIGN KEY (role_id) REFERENCES roles(role_id)
);
