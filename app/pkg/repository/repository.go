package repository

import (
	"context"
	"fmt"

	"github.com/Nerzal/gocloak/v12"
)

type UserRepository struct {
	client gocloak.GoCloak
	realm  string
}

func NewRepository(client gocloak.GoCloak, realm string) *UserRepository {
	return &UserRepository{
		client: client,
		realm:  realm,
	}
}

func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*gocloak.User, error) {
	_, err := r.GetAdminToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin token: %v", err)
	}
	users, err := r.GetUsers(ctx, gocloak.GetUsersParams{
		Email: gocloak.StringP(email),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %v", err)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("user not found with email: %s", email)
	}
	return users[0], nil
}

func (r *UserRepository) GetUserByID(ctx context.Context, userID string) (*gocloak.User, error) {
	token, err := r.GetAdminToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin token: %v", err)
	}
	user, err := r.client.GetUserByID(ctx, token.AccessToken, r.realm, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID: %v", err)
	}
	return user, nil
}

func (r *UserRepository) CreateUser(ctx context.Context, user gocloak.User) (string, error) {
	token, err := r.GetAdminToken(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get admin token: %v", err)
	}
	userID, err := r.client.CreateUser(ctx, token.AccessToken, r.realm, user)
	if err != nil {
		return "", fmt.Errorf("failed to create user: %v", err)
	}
	return userID, nil
}

func (r *UserRepository) UpdateUser(ctx context.Context, user gocloak.User) error {
	token, err := r.GetAdminToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get admin token: %v", err)
	}
	err = r.client.UpdateUser(ctx, token.AccessToken, r.realm, user)
	if err != nil {
		return fmt.Errorf("failed to update user: %v", err)
	}
	return nil
}

func (r *UserRepository) SetPassword(ctx context.Context, userID, password string, temporary bool) error {
	token, err := r.GetAdminToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get admin token: %v", err)
	}
	err = r.client.SetPassword(ctx, token.AccessToken, userID, r.realm, password, temporary)
	if err != nil {
		return fmt.Errorf("failed to set password: %v", err)
	}
	return nil
}

func (r *UserRepository) GetUsers(ctx context.Context, params gocloak.GetUsersParams) ([]*gocloak.User, error) {
	token, err := r.GetAdminToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin token: %v", err)
	}
	users, err := r.client.GetUsers(ctx, token.AccessToken, r.realm, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %v", err)
	}
	return users, nil
}

func (r *UserRepository) GetAdminToken(ctx context.Context) (*gocloak.JWT, error) {
	return r.client.LoginAdmin(ctx, "admin", "password", r.realm)
}
