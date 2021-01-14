package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"
	database "github.com/softcorp-io/hqs-privileges-service/database"
	handler "github.com/softcorp-io/hqs-privileges-service/handler"
	repository "github.com/softcorp-io/hqs-privileges-service/repository"
	privilegeProto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_privilege_service"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type collectionEnv struct {
	privilegeCollection string
	userCollection      string
}

// Init - initialize .env variables.
func Init(zapLog *zap.Logger) {
	if err := godotenv.Load("hqs.env"); err != nil {
		zapLog.Error(fmt.Sprintf("Could not load hqs.env with err %v", err))
	}
}

func loadCollections() (collectionEnv, error) {
	privilegeCollection, ok := os.LookupEnv("MONGO_DB_PRIVILEGE_COLLECTION")
	if !ok {
		return collectionEnv{}, errors.New("Required MONGO_DB_PRIVILEGE_COLLECTION")
	}
	userCollection, ok := os.LookupEnv("MONGO_DB_USER_COLLECTION")
	if !ok {
		return collectionEnv{}, errors.New("Required MONGO_DB_USER_COLLECTION")
	}
	return collectionEnv{privilegeCollection, userCollection}, nil
}

// Run - runs a go microservice. Uses zap for logging and a waitGroup for async testing.
func Run(zapLog *zap.Logger, wg *sync.WaitGroup) {
	// creates a database connection and closes it when done
	mongoenv, err := database.GetMongoEnv()
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not set up mongo env with err %v", err))
	}
	// build uri for mongodb
	mongouri := fmt.Sprintf("mongodb+srv://%s:%s@%s/%s?retryWrites=true&w=majority", mongoenv.User, mongoenv.Password, mongoenv.Host, mongoenv.DBname)

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	mongo, err := database.NewMongoDatabase(ctx, zapLog, mongouri)
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not make connection to DB with err %v", err))
	}

	defer mongo.Disconnect(context.Background())

	mongodb := mongo.Database(mongoenv.DBname)

	collections, err := loadCollections()
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Could not load collections with err: %v", err))
	}

	privilegeCollection := mongodb.Collection(collections.privilegeCollection)
	usersCollection := mongodb.Collection(collections.userCollection)

	// setup repository
	repo := repository.NewRepository(privilegeCollection, usersCollection)

	if err := repo.CreateDefault(context.Background()); err != nil {
		zapLog.Info(fmt.Sprintf("%v", err))
	} else {
		zapLog.Info("Created default privilege!")
	}
	if err := repo.CreateRoot(context.Background()); err != nil {
		zapLog.Info(fmt.Sprintf("%v", err))
	} else {
		zapLog.Info("Created root privilege!")
	}

	// use above to create handler
	handle := handler.NewHandler(repo, zapLog)

	// create the service and run the service
	port, ok := os.LookupEnv("SERVICE_PORT")
	if !ok {
		zapLog.Fatal("Could not get service port")
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		zapLog.Fatal(fmt.Sprintf("Failed to listen with err %v", err))
	}
	defer lis.Close()

	zapLog.Info(fmt.Sprintf("Service running on port: %s", port))

	// setup grpc
	grpcServer := grpc.NewServer()

	// register handler
	privilegeProto.RegisterPrivilegeServiceServer(grpcServer, handle)

	// run the server
	if err := grpcServer.Serve(lis); err != nil {
		zapLog.Fatal(fmt.Sprintf("Failed to serve with err %v", err))
	}
}
