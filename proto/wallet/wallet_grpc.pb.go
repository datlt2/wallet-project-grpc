// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.12.4
// source: wallet/wallet.proto

package wallet

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// WalletServiceClient is the client API for WalletService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type WalletServiceClient interface {
	CreateWallet(ctx context.Context, in *SingleUserRequest, opts ...grpc.CallOption) (*SingleResponse, error)
	ReadWallet(ctx context.Context, in *SingleUserRequest, opts ...grpc.CallOption) (*ReadWalletResponse, error)
	CreateTransaction(ctx context.Context, in *CreateTransactionRequest, opts ...grpc.CallOption) (*SingleResponse, error)
	ReadTransactions(ctx context.Context, in *SingleUserRequest, opts ...grpc.CallOption) (*ReadTransactionsResponse, error)
}

type walletServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewWalletServiceClient(cc grpc.ClientConnInterface) WalletServiceClient {
	return &walletServiceClient{cc}
}

func (c *walletServiceClient) CreateWallet(ctx context.Context, in *SingleUserRequest, opts ...grpc.CallOption) (*SingleResponse, error) {
	out := new(SingleResponse)
	err := c.cc.Invoke(ctx, "/grpc.component.com.proto.wallet.WalletService/CreateWallet", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *walletServiceClient) ReadWallet(ctx context.Context, in *SingleUserRequest, opts ...grpc.CallOption) (*ReadWalletResponse, error) {
	out := new(ReadWalletResponse)
	err := c.cc.Invoke(ctx, "/grpc.component.com.proto.wallet.WalletService/ReadWallet", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *walletServiceClient) CreateTransaction(ctx context.Context, in *CreateTransactionRequest, opts ...grpc.CallOption) (*SingleResponse, error) {
	out := new(SingleResponse)
	err := c.cc.Invoke(ctx, "/grpc.component.com.proto.wallet.WalletService/CreateTransaction", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *walletServiceClient) ReadTransactions(ctx context.Context, in *SingleUserRequest, opts ...grpc.CallOption) (*ReadTransactionsResponse, error) {
	out := new(ReadTransactionsResponse)
	err := c.cc.Invoke(ctx, "/grpc.component.com.proto.wallet.WalletService/ReadTransactions", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WalletServiceServer is the server API for WalletService service.
// All implementations must embed UnimplementedWalletServiceServer
// for forward compatibility
type WalletServiceServer interface {
	CreateWallet(context.Context, *SingleUserRequest) (*SingleResponse, error)
	ReadWallet(context.Context, *SingleUserRequest) (*ReadWalletResponse, error)
	CreateTransaction(context.Context, *CreateTransactionRequest) (*SingleResponse, error)
	ReadTransactions(context.Context, *SingleUserRequest) (*ReadTransactionsResponse, error)
	mustEmbedUnimplementedWalletServiceServer()
}

// UnimplementedWalletServiceServer must be embedded to have forward compatible implementations.
type UnimplementedWalletServiceServer struct {
}

func (UnimplementedWalletServiceServer) CreateWallet(context.Context, *SingleUserRequest) (*SingleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateWallet not implemented")
}
func (UnimplementedWalletServiceServer) ReadWallet(context.Context, *SingleUserRequest) (*ReadWalletResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReadWallet not implemented")
}
func (UnimplementedWalletServiceServer) CreateTransaction(context.Context, *CreateTransactionRequest) (*SingleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateTransaction not implemented")
}
func (UnimplementedWalletServiceServer) ReadTransactions(context.Context, *SingleUserRequest) (*ReadTransactionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReadTransactions not implemented")
}
func (UnimplementedWalletServiceServer) mustEmbedUnimplementedWalletServiceServer() {}

// UnsafeWalletServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to WalletServiceServer will
// result in compilation errors.
type UnsafeWalletServiceServer interface {
	mustEmbedUnimplementedWalletServiceServer()
}

func RegisterWalletServiceServer(s grpc.ServiceRegistrar, srv WalletServiceServer) {
	s.RegisterService(&WalletService_ServiceDesc, srv)
}

func _WalletService_CreateWallet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SingleUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WalletServiceServer).CreateWallet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.component.com.proto.wallet.WalletService/CreateWallet",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WalletServiceServer).CreateWallet(ctx, req.(*SingleUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _WalletService_ReadWallet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SingleUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WalletServiceServer).ReadWallet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.component.com.proto.wallet.WalletService/ReadWallet",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WalletServiceServer).ReadWallet(ctx, req.(*SingleUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _WalletService_CreateTransaction_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateTransactionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WalletServiceServer).CreateTransaction(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.component.com.proto.wallet.WalletService/CreateTransaction",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WalletServiceServer).CreateTransaction(ctx, req.(*CreateTransactionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _WalletService_ReadTransactions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SingleUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WalletServiceServer).ReadTransactions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.component.com.proto.wallet.WalletService/ReadTransactions",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WalletServiceServer).ReadTransactions(ctx, req.(*SingleUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// WalletService_ServiceDesc is the grpc.ServiceDesc for WalletService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var WalletService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "grpc.component.com.proto.wallet.WalletService",
	HandlerType: (*WalletServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateWallet",
			Handler:    _WalletService_CreateWallet_Handler,
		},
		{
			MethodName: "ReadWallet",
			Handler:    _WalletService_ReadWallet_Handler,
		},
		{
			MethodName: "CreateTransaction",
			Handler:    _WalletService_CreateTransaction_Handler,
		},
		{
			MethodName: "ReadTransactions",
			Handler:    _WalletService_ReadTransactions_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "wallet/wallet.proto",
}
