package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/golang/protobuf/ptypes"
	uuid "github.com/satori/go.uuid"
	privilegeProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_privilege_service"
)

// Privilege - struct.
type Privilege struct {
	ID                     string    `bson:"id" json:"id"`
	Name                   string    `bson:"name" json:"name"`
	ViewAllUsers           bool      `bson:"view_all_users" json:"view_all_users"`
	CreateUser             bool      `bson:"create_user" json:"create_user"`
	ManagePrivileges       bool      `bson:"manage_privileges" json:"manage_privileges"`
	DeleteUser             bool      `bson:"delete_user" json:"delete_user"`
	BlockUser              bool      `bson:"block_user" json:"block_user"`
	SendResetPasswordEmail bool      `bson:"send_reset_password_email" json:"send_reset_password_email"`
	CreatedAt              time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt              time.Time `bson:"updated_at" json:"updated_at"`
	Default                bool      `bson:"default" json:"default"`
	Root                   bool      `bson:"root" json:"root"`
}

// Repository - interface.
type Repository interface {
	Create(ctx context.Context, priv *Privilege) error
	CreateDefault(ctx context.Context) error
	Update(ctx context.Context, priv *Privilege) error
	Get(ctx context.Context, priv *Privilege) (*Privilege, error)
	GetDefault(ctx context.Context) (*Privilege, error)
	GetRoot(ctx context.Context) (*Privilege, error)
	GetAll(ctx context.Context) ([]*Privilege, error)
	Delete(ctx context.Context, priv *Privilege) error
}

// MongoRepository - struct.
type MongoRepository struct {
	mongo     *mongo.Collection
	mongoUser *mongo.Collection
}

// NewRepository - returns MongoRepository pointer.
func NewRepository(mongo *mongo.Collection, mongoUser *mongo.Collection) *MongoRepository {
	return &MongoRepository{mongo, mongoUser}
}

// MarshalPrivilegeCollection - unmarshal collection from proto.privilege to privileges
func MarshalPrivilegeCollection(privileges []*privilegeProto.Privilege) []*Privilege {
	u := []*Privilege{}
	for _, priv := range privileges {
		u = append(u, MarshalPrivilege(priv))
	}
	return u
}

// MarshalPrivilege - proto -> repo
func MarshalPrivilege(priv *privilegeProto.Privilege) *Privilege {
	createdAt, _ := ptypes.Timestamp(priv.CreatedAt)
	updatedAt, _ := ptypes.Timestamp(priv.UpdatedAt)
	return &Privilege{
		ID:                     priv.Id,
		Name:                   priv.Name,
		ViewAllUsers:           priv.ViewAllUsers,
		CreateUser:             priv.CreateUser,
		ManagePrivileges:       priv.ManagePrivileges,
		DeleteUser:             priv.DeleteUser,
		BlockUser:              priv.BlockUser,
		SendResetPasswordEmail: priv.SendResetPasswordEmail,
		Root:                   priv.Root,
		Default:                priv.Default,
		CreatedAt:              createdAt,
		UpdatedAt:              updatedAt,
	}
}

// UnmarshalPrivlegeCollection - unmarshal priv to proto
func UnmarshalPrivlegeCollection(privileges []*Privilege) []*privilegeProto.Privilege {
	u := []*privilegeProto.Privilege{}
	for _, priv := range privileges {
		u = append(u, UnmarshalPrivilege(priv))
	}
	return u
}

// UnmarshalPrivilege - repo -> proto.
func UnmarshalPrivilege(priv *Privilege) *privilegeProto.Privilege {
	createdAt, _ := ptypes.TimestampProto(priv.CreatedAt)
	updatedAt, _ := ptypes.TimestampProto(priv.UpdatedAt)
	return &privilegeProto.Privilege{
		Id:                     priv.ID,
		Name:                   priv.Name,
		ViewAllUsers:           priv.ViewAllUsers,
		CreateUser:             priv.CreateUser,
		ManagePrivileges:       priv.ManagePrivileges,
		DeleteUser:             priv.DeleteUser,
		BlockUser:              priv.BlockUser,
		SendResetPasswordEmail: priv.SendResetPasswordEmail,
		Root:                   priv.Root,
		Default:                priv.Default,
		CreatedAt:              createdAt,
		UpdatedAt:              updatedAt,
	}
}

// Validate - validates privileges bools.
func (p *Privilege) validate(action string) error {
	switch action {
	case "create":
		createNoViewAccess := p.CreateUser && !p.ViewAllUsers
		deleteNoViewAccess := p.DeleteUser && !p.ViewAllUsers
		managePrivilegesNoViewAccess := p.ManagePrivileges && !p.ViewAllUsers
		blockNoViewAccess := p.BlockUser && !p.ViewAllUsers
		sendResetEmailNoViewAccess := p.SendResetPasswordEmail && !p.ViewAllUsers
		if createNoViewAccess {
			return errors.New("Create access not allowed without view access")
		}
		if deleteNoViewAccess {
			return errors.New("Delete access not allowed without view access")
		}
		if managePrivilegesNoViewAccess {
			return errors.New("Manage privileges access not allowed without view access")
		}
		if blockNoViewAccess {
			return errors.New("Block access not allowed without view access")
		}
		if sendResetEmailNoViewAccess {
			return errors.New("Send reset email access not allowed without view access")
		}
		if p.Name == "" {
			return errors.New("Name is required")
		}
		if p.ID == "" {
			return errors.New("Name is required")
		}
	case "update":
		if p.Default || p.Root {
			return errors.New("Cannot update root privilege")
		}
		createNoViewAccess := p.CreateUser && !p.ViewAllUsers
		deleteNoViewAccess := p.DeleteUser && !p.ViewAllUsers
		managePrivilegesNoViewAccess := p.ManagePrivileges && !p.ViewAllUsers
		blockNoViewAccess := p.BlockUser && !p.ViewAllUsers
		sendResetEmailNoViewAccess := p.SendResetPasswordEmail && !p.ViewAllUsers
		if createNoViewAccess {
			return errors.New("Create access bot allowed without view access")
		}
		if deleteNoViewAccess {
			return errors.New("Delete access not allowed without view access")
		}
		if managePrivilegesNoViewAccess {
			return errors.New("Manage privileges access not allowed without view access")
		}
		if blockNoViewAccess {
			return errors.New("Block access not allowed without view access")
		}
		if sendResetEmailNoViewAccess {
			return errors.New("Send reset email access not allowed without view access")
		}
		if p.Name == "" {
			return errors.New("Name is required")
		}
		if p.ID == "" {
			return errors.New("Name is required")
		}
	case "delete":
		if p.Default || p.Root {
			return errors.New("Cannot delete root privilege")
		}
	default:
		return errors.New("Unknown action")
	}
	return nil
}

func (p *Privilege) prepare(action string) {
	switch strings.ToLower(action) {
	case "create":
		p.Default = false
		p.Root = false
		p.CreatedAt = time.Now()
		p.UpdatedAt = time.Now()
		break
	case "update":
		p.Default = false
		p.Root = false
		p.UpdatedAt = time.Now()
		break
	}
}

// Create - creates a new privilege.
func (r *MongoRepository) Create(ctx context.Context, priv *Privilege) error {
	priv.ID = uuid.NewV4().String()

	priv.prepare("create")

	if err := priv.validate("create"); err != nil {
		return err
	}

	_, err := r.mongo.InsertOne(ctx, priv)
	if err != nil {
		return err
	}

	return nil
}

// CreateDefault - creates a new default privilege.
func (r *MongoRepository) CreateDefault(ctx context.Context) error {
	_, err := r.GetDefault(ctx)
	if err == nil {
		return errors.New("Default privilege already exists")
	}

	priv := &Privilege{
		ID:                     uuid.NewV4().String(),
		Name:                   "Default",
		ViewAllUsers:           false,
		CreateUser:             false,
		ManagePrivileges:       false,
		DeleteUser:             false,
		BlockUser:              false,
		SendResetPasswordEmail: false,
		Default:                true,
	}

	_, err = r.mongo.InsertOne(ctx, priv)
	if err != nil {
		return err
	}

	return nil
}

// CreateRoot - creates a new default privilege.
func (r *MongoRepository) CreateRoot(ctx context.Context) error {
	_, err := r.GetRoot(ctx)
	if err == nil {
		return errors.New("Root privilege already exists")
	}

	priv := &Privilege{
		ID:                     uuid.NewV4().String(),
		Name:                   "Root",
		ViewAllUsers:           true,
		CreateUser:             true,
		ManagePrivileges:       true,
		DeleteUser:             true,
		BlockUser:              true,
		SendResetPasswordEmail: true,
		Root:                   true,
	}

	_, err = r.mongo.InsertOne(ctx, priv)
	if err != nil {
		return err
	}

	return nil
}

// Update - updates existing privilege by id
func (r *MongoRepository) Update(ctx context.Context, priv *Privilege) error {
	priv.prepare("update")

	if err := priv.validate("update"); err != nil {
		return err
	}

	updatePrivilege := bson.M{
		"$set": bson.M{
			"name":                      priv.Name,
			"view_all_users":            priv.ViewAllUsers,
			"create_user":               priv.CreateUser,
			"manage_privileges":         priv.ManagePrivileges,
			"delete_user":               priv.DeleteUser,
			"block_user":                priv.BlockUser,
			"send_reset_password_email": priv.SendResetPasswordEmail,
			"updated_at":                time.Now(),
		},
	}

	_, err := r.mongo.UpdateOne(
		ctx,
		bson.M{"id": priv.ID},
		updatePrivilege,
	)

	if err != nil {
		return err
	}

	return nil
}

// Get - finds single privilege using the privilege's id.
func (r *MongoRepository) Get(ctx context.Context, priv *Privilege) (*Privilege, error) {
	privReturn := Privilege{}

	if err := r.mongo.FindOne(ctx, bson.M{"id": priv.ID}).Decode(&privReturn); err != nil {
		return nil, err
	}

	return &privReturn, nil
}

// GetDefault - returns default certificate
func (r *MongoRepository) GetDefault(ctx context.Context) (*Privilege, error) {
	rootPriv := Privilege{}
	if err := r.mongo.FindOne(ctx, bson.M{"default": true}).Decode(&rootPriv); err != nil {
		return &Privilege{}, err
	}
	return &rootPriv, nil
}

// GetRoot - returns root certificate
func (r *MongoRepository) GetRoot(ctx context.Context) (*Privilege, error) {
	rootPriv := Privilege{}
	if err := r.mongo.FindOne(ctx, bson.M{"root": true}).Decode(&rootPriv); err != nil {
		return &Privilege{}, err
	}
	return &rootPriv, nil
}

// GetAll - returns every privilege in the system.
func (r *MongoRepository) GetAll(ctx context.Context) ([]*Privilege, error) {
	privsReturn := []*Privilege{}

	cursor, err := r.mongo.Find(context.TODO(), bson.M{})

	if err != nil {
		return []*Privilege{}, err
	}

	for cursor.Next(ctx) {
		var tempPriv Privilege
		cursor.Decode(&tempPriv)

		privsReturn = append(privsReturn, &tempPriv)
	}

	return privsReturn, nil
}

// Delete - deletes a given privilege by id.
func (r *MongoRepository) Delete(ctx context.Context, priv *Privilege) error {
	if err := priv.validate("delete"); err != nil {
		return err
	}

	// set all users with that privilege to default privilege
	defaultPrivilege, err := r.GetDefault(ctx)
	if err != nil {
		return err
	}
	updateUsers := bson.M{
		"$set": bson.M{
			"privilege_id": defaultPrivilege.ID,
			"updated_at":   time.Now(),
		},
	}
	_, err = r.mongoUser.UpdateMany(
		ctx,
		bson.M{"privilege_id": priv.ID},
		updateUsers,
	)

	if err != nil {
		return err
	}

	// now delete
	_, err = r.mongo.DeleteOne(ctx, bson.M{"id": priv.ID})
	if err != nil {
		return err
	}

	return nil
}
