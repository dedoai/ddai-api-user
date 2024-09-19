package repository

import (
	"context"
	"fmt"

	"github.com/Nerzal/gocloak/v12"
	"github.com/dedoai/ddai-api-user/models"
)

type UserRepository interface {
	GetUserByEmail(ctx context.Context, email string) (*gocloak.User, error)
	GetUserByID(ctx context.Context, userID string) (*gocloak.User, error)
	CreateUser(ctx context.Context, user gocloak.User) (string, error)
	UpdateUser(ctx context.Context, user gocloak.User) error
	SetPassword(ctx context.Context, userID, password string, temporary bool) error
	GetUsers(ctx context.Context, params gocloak.GetUsersParams) ([]*gocloak.User, error)
	GetAdminToken(ctx context.Context) (*gocloak.JWT, error)
}

type userRepository struct {
	client  gocloak.GoCloak
	realm   string
	options *models.Options
}

func NewRepository(client gocloak.GoCloak, realm string, options *models.Options) UserRepository {
	return &userRepository{
		client:  client,
		realm:   realm,
		options: options,
	}
}

func (r *userRepository) GetUserByEmail(ctx context.Context, email string) (*gocloak.User, error) {
	users, err := r.GetUsers(ctx, gocloak.GetUsersParams{Email: gocloak.StringP(email)})
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %v", err)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("user not found with email: %s", email)
	}
	return users[0], nil
}

func (r *userRepository) GetUserByID(ctx context.Context, userID string) (*gocloak.User, error) {
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

func (r *userRepository) CreateUser(ctx context.Context, user gocloak.User) (string, error) {
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

func (r *userRepository) UpdateUser(ctx context.Context, user gocloak.User) error {
	token, err := r.GetAdminToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get admin token: %v", err)
	}
	fmt.Println("update", token.AccessToken, user.Attributes)
	err = r.client.UpdateUser(ctx, token.AccessToken, r.realm, gocloak.User{
		ID:         user.ID,
		Email:      user.Email,
		FirstName:  user.FirstName,
		LastName:   user.LastName,
		Attributes: user.Attributes,
	})
	if err != nil {
		return fmt.Errorf("failed to update user: %v", err)
	}
	return nil
}

func (r *userRepository) SetPassword(ctx context.Context, userID, password string, temporary bool) error {
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

func (r *userRepository) GetUsers(ctx context.Context, params gocloak.GetUsersParams) ([]*gocloak.User, error) {
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

func (r *userRepository) GetAdminToken(ctx context.Context) (*gocloak.JWT, error) {
	return r.client.LoginAdmin(ctx, r.options.ClientID, r.options.ClientSecret, r.realm)
}
