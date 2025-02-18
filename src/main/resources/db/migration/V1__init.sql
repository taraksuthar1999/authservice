CREATE TABLE roles
(
    id         BIGINT AUTO_INCREMENT NOT NULL,
    is_deleted BIT(1) DEFAULT 0 NULL,
    is_active  BIT(1) DEFAULT 1 NULL,
    created_at datetime NULL,
    updated_at datetime NULL,
    name       VARCHAR(255) NOT NULL,
    CONSTRAINT pk_roles PRIMARY KEY (id)
);

CREATE TABLE session
(
    id         BIGINT AUTO_INCREMENT NOT NULL,
    is_deleted BIT(1) DEFAULT 0 NULL,
    is_active  BIT(1) DEFAULT 1 NULL,
    created_at datetime NULL,
    updated_at datetime NULL,
    user_id    BIGINT NULL,
    token      VARCHAR(255) NULL,
    ip_address VARCHAR(255) NULL,
    expiry_at  datetime NULL,
    issued_at  datetime NULL,
    CONSTRAINT pk_session PRIMARY KEY (id)
);

CREATE TABLE user
(
    id           BIGINT AUTO_INCREMENT NOT NULL,
    is_deleted   BIT(1) DEFAULT 0 NULL,
    is_active    BIT(1) DEFAULT 1 NULL,
    created_at   datetime NULL,
    updated_at   datetime NULL,
    name         VARCHAR(255) NOT NULL,
    email        VARCHAR(255) NOT NULL,
    password     VARCHAR(255) NOT NULL,
    profile      VARCHAR(255) NOT NULL,
    is_verified  BIT(1) DEFAULT 0 NULL,
    verify_token VARCHAR(255) NULL,
    CONSTRAINT pk_user PRIMARY KEY (id)
);

CREATE TABLE user_roles
(
    user_id  BIGINT NOT NULL,
    roles_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, roles_id)
);

ALTER TABLE roles
    ADD CONSTRAINT uc_roles_name UNIQUE (name);

ALTER TABLE user
    ADD CONSTRAINT uc_user_email UNIQUE (email);

ALTER TABLE session
    ADD CONSTRAINT FK_SESSION_ON_USER FOREIGN KEY (user_id) REFERENCES user (id);

ALTER TABLE user_roles
    ADD CONSTRAINT fk_userol_on_roles FOREIGN KEY (roles_id) REFERENCES roles (id);

ALTER TABLE user_roles
    ADD CONSTRAINT fk_userol_on_user FOREIGN KEY (user_id) REFERENCES user (id);