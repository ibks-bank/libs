package auth

import (
	"context"
	"strings"

	"github.com/ibks-bank/libs/cerr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	UserKey     = "X-Auth-User"
	TokenKey    = "X-Auth-Token"
	TelegramKey = "X-Auth-Telegram"
)

type userInfo struct {
	Username string
	Password string
	UserID   int64
}

func (a *authorizer) Interceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {

	var err error

	switch info.FullMethod {
	case "/profile_pb.Profile/SignUp",
		"/profile_pb.Profile/SignIn",
		"/profile_pb.Profile/SubmitCode",
		"/profile_pb.Profile/SetAuthenticationCode":

	default:
		ctx, err = a.authorize(ctx)
		if err != nil {
			return nil, err
		}
	}

	return handler(ctx, req)
}

func (a *authorizer) authorize(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, status.Errorf(codes.InvalidArgument, "Retrieving metadata is failed")
	}

	authHeader, ok := md[strings.ToLower(TokenKey)]
	if !ok {
		return ctx, status.Errorf(codes.Unauthenticated, "Authorization token is not supplied")
	}

	token := authHeader[0]

	username, password, userID, err := ParseToken(token, []byte(a.key))
	if err != nil {
		return ctx, status.Errorf(codes.Unauthenticated, err.Error())
	}

	return context.WithValue(ctx, UserKey, userInfo{Username: username, Password: password, UserID: userID}), nil
}

func GetUserInfo(ctx context.Context) (*userInfo, error) {
	user, ok := ctx.Value(UserKey).(userInfo)
	if !ok {
		return nil, cerr.NewC("user info not found in context", codes.Unauthenticated)
	}

	return &user, nil
}

func GetTelegramUsername(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Errorf(codes.InvalidArgument, "Retrieving metadata is failed")
	}

	tgHeader, ok := md[strings.ToLower(TelegramKey)]
	if !ok {
		return "", nil
	}

	return tgHeader[0], nil
}
