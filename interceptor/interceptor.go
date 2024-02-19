package interceptor

import (
	"context"
	jwtHelepr "github.com/datlt2/wallet-project-helper/jwt"
	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"time"
)

// Interceptor for logging
func LoggingInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (resp interface{}, err error) {

	startTime := time.Now()

	grpclog.Infof("Request started: %s", info.FullMethod)
	grpclog.Infof("Request content: %s", req)

	// Proceed with the request
	resp, err = handler(ctx, req)
	grpclog.Infof("Response content: %s", resp)
	grpclog.Infof("Request completed: %s, Duration: %s", info.FullMethod, time.Since(startTime))

	return resp, err
}

// Interceptor for authorization
func AuthorizationInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	grpclog.Infof("Authorization process")

	// Check metadata exist
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		grpclog.Infof("Metadata not found")
		return nil, status.Error(codes.InvalidArgument, "Metadata not found")
	}

	// Check token exist
	if len(md["authorization"]) == 0 || len(md["authorization"][0]) == 0 {
		grpclog.Infof("Missing authorization token")
		return nil, status.Error(codes.InvalidArgument, "Missing authorization token")
	}

	// Parse token and get token info (payload)
	token, err := jwtHelepr.VerifyToken(md["authorization"][0])
	if err != nil {
		grpclog.Infof("Invalid token %v", md["authorization"][0])
		return nil, status.Error(codes.Unauthenticated, "Invalid token")
	}
	tokenInfo := token.Claims.(jwt.MapClaims)
	grpclog.Infof("Token Info %v", tokenInfo)

	// Verify token info (payload) - authorization step
	if ok, err := jwtHelepr.VerifyTokenInfo(tokenInfo); !ok {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	// Proceed with the request
	return handler(ctx, req)
}
