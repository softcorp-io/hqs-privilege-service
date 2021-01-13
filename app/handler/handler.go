package handler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	repository "github.com/softcorp-io/hqs-privileges-service/repository"
	privilegeProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_privilege_service"
	userProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"
)

// Handler - struct used through program and passed to go-micro.
type Handler struct {
	repository repository.Repository
	zapLog     *zap.Logger
}

// NewHandler returns a Handler object
func NewHandler(repo repository.Repository, zapLog *zap.Logger) *Handler {
	return &Handler{repo, zapLog}
}

// Ping - used for other service to check if live
func (s *Handler) Ping(ctx context.Context, req *privilegeProto.Request) (*privilegeProto.Response, error) {
	s.zapLog.Info("Recieved new request")
	return &privilegeProto.Response{}, nil
}

// Create - creates a new privilege and stores it in the database
func (s *Handler) Create(ctx context.Context, req *privilegeProto.Privilege) (*privilegeProto.Response, error) {
	s.zapLog.Info("Recieved new request")
	if err := s.validateTokenHelper(ctx); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate user with err %v", err))
		return &privilegeProto.Response{}, err
	}

	if err := s.repository.Create(ctx, repository.MarshalPrivilege(req)); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not create privilege with err %v", err))
		return &privilegeProto.Response{}, err
	}
	return &privilegeProto.Response{}, nil
}

// Update - updates an existing privilege
func (s *Handler) Update(ctx context.Context, req *privilegeProto.Privilege) (*privilegeProto.Response, error) {
	s.zapLog.Info("Recieved new request")
	if err := s.validateTokenHelper(ctx); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate user with err %v", err))
		return &privilegeProto.Response{}, err
	}

	if err := s.repository.Update(ctx, repository.MarshalPrivilege(req)); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not update privilege with err %v", err))
		return &privilegeProto.Response{}, err
	}
	return &privilegeProto.Response{}, nil
}

// Get - gets a privilege by its id
func (s *Handler) Get(ctx context.Context, req *privilegeProto.Privilege) (*privilegeProto.Response, error) {
	privilege, err := s.repository.Get(ctx, repository.MarshalPrivilege(req))
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get privilege with err %v", err))
		return &privilegeProto.Response{}, err
	}

	rep := &privilegeProto.Response{}
	rep.Privilege = repository.UnmarshalPrivilege(privilege)

	return &privilegeProto.Response{}, nil
}

// GetRoot - gets a root privilege
func (s *Handler) GetRoot(ctx context.Context, req *privilegeProto.Request) (*privilegeProto.Response, error) {
	privilege, err := s.repository.GetRoot(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get root privilege with err %v", err))
		return &privilegeProto.Response{}, err
	}

	rep := &privilegeProto.Response{}
	rep.Privilege = repository.UnmarshalPrivilege(privilege)

	return &privilegeProto.Response{}, nil
}

// GetDefault - gets a default privilege
func (s *Handler) GetDefault(ctx context.Context, req *privilegeProto.Request) (*privilegeProto.Response, error) {
	privilege, err := s.repository.GetDefault(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get default privilege with err %v", err))
		return &privilegeProto.Response{}, err
	}

	rep := &privilegeProto.Response{}
	rep.Privilege = repository.UnmarshalPrivilege(privilege)

	return &privilegeProto.Response{}, nil
}

// GetAll - get all privileges
func (s *Handler) GetAll(ctx context.Context, req *privilegeProto.Request) (*privilegeProto.Response, error) {
	privileges, err := s.repository.GetAll(ctx)
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get all privileges with err %v", err))
		return &privilegeProto.Response{}, err
	}

	rep := &privilegeProto.Response{}
	rep.Privileges = repository.UnmarshalPrivlegeCollection(privileges)

	return &privilegeProto.Response{}, nil
}

// Delete - deltes a privilege
func (s *Handler) Delete(ctx context.Context, req *privilegeProto.Privilege) (*privilegeProto.Response, error) {
	s.zapLog.Info("Recieved new request")
	if err := s.validateTokenHelper(ctx); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not validate user with err %v", err))
		return &privilegeProto.Response{}, err
	}

	if err := s.repository.Delete(ctx, repository.MarshalPrivilege(req)); err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not get privilege with err %v", err))
		return &privilegeProto.Response{}, err
	}

	return &privilegeProto.Response{}, nil
}

// s.validateTokenHelper - helper function to validate tokens inside functions in Handler
func (s *Handler) validateTokenHelper(ctx context.Context) error {
	meta, ok := metadata.FromIncomingContext(ctx)

	if !ok {
		s.zapLog.Error("Could not validate token")
		return errors.New("Could not validate token")
	}

	token := meta["token"]

	if len(token) == 0 {
		s.zapLog.Error("Missing token header in context")
		return errors.New("Missing token header in context")
	}

	if strings.Trim(token[0], " ") == "" {
		s.zapLog.Error("Token is empty")
		return errors.New("Token is empty")
	}

	userToken := &userProto.Token{
		Token: token[0],
	}

	// setup user client
	ip, check := os.LookupEnv("USER_SERVICE_IP")
	if !check {
		s.zapLog.Error("Required USER_SERVICE_IP")
		return errors.New("Required USER_SERVICE_IP")
	}
	port, check := os.LookupEnv("USER_SERVICE_PORT")
	if !check {
		s.zapLog.Error("Required USER_SERVICE_PORT")
		return errors.New("Required USER_SERVICE_PORT")
	}

	conn, err := grpc.DialContext(context.Background(), ip+":"+port, grpc.WithInsecure())
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not dial user service with err %v", err))
		return err
	}
	defer conn.Close()
	userClient := userProto.NewUserServiceClient(conn)

	_, err = userClient.Ping(context.Background(), &userProto.Request{})
	if err != nil {
		s.zapLog.Error(fmt.Sprintf("Could not ping user service with err %v", err))
		return err
	}

	// validate token
	resultToken, err := userClient.ValidateToken(context.Background(), userToken)
	if err != nil {
		return err
	}
	if resultToken.ManagePrivileges == false {
		return errors.New("User not allowed to manage privileges")
	}

	return nil
}
