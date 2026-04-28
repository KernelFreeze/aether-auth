package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hokamsingh/go-backend-template/internal/models"
	"github.com/hokamsingh/go-backend-template/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// UserService struct manages user-related operations.
type UserService struct {
	repo *repository.UserRepository
}

// CreateUserInput defines user creation fields.
type CreateUserInput struct {
	Email     string
	Password  string
	FirstName string
	LastName  string
}

// UpdateUserInput defines fields allowed for update.
type UpdateUserInput struct {
	FirstName *string
	LastName  *string
	Active    *bool
}

// NewUserService initializes UserService.
func NewUserService(repo *repository.UserRepository) *UserService {
	return &UserService{repo: repo}
}

// GetByID fetches a user by ID
func (s *UserService) GetByID(ctx context.Context, id uint) (*models.User, error) {
	return s.repo.GetByID(ctx, id)
}

// Create hashes password and creates a new user.
func (s *UserService) Create(ctx context.Context, input CreateUserInput) (*models.User, error) {
	hashedPassword, err := hashPassword(input.Password)
	if err != nil {
		return nil, fmt.Errorf("password hashing failed: %w", err)
	}

	user := &models.User{
		Email:     input.Email,
		Password:  hashedPassword,
		FirstName: input.FirstName,
		LastName:  input.LastName,
		Active:    true,
	}

	if err := s.repo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// Update modifies user attributes if provided.
func (s *UserService) Update(ctx context.Context, id uint, input UpdateUserInput) (*models.User, error) {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user: %w", err)
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	// Apply updates only if fields are provided
	if input.FirstName != nil {
		user.FirstName = *input.FirstName
	}
	if input.LastName != nil {
		user.LastName = *input.LastName
	}
	if input.Active != nil {
		user.Active = *input.Active
	}

	if err := s.repo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return user, nil
}

// UpdateLastLogin sets the last login timestamp.
func (s *UserService) UpdateLastLogin(ctx context.Context, id uint) error {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to fetch user: %w", err)
	}
	if user == nil {
		return errors.New("user not found")
	}

	user.LastLogin = time.Now()

	if err := s.repo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// hashPassword generates a bcrypt hash for a given password.
func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}
