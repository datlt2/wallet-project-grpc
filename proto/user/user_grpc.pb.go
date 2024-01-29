// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.12.4
// source: user/user.proto

package user

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

// UserServiceClient is the client API for UserService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type UserServiceClient interface {
	Create(ctx context.Context, in *UserRequest, opts ...grpc.CallOption) (*SingleResponse, error)
	Read(ctx context.Context, in *SingleUserRequest, opts ...grpc.CallOption) (*UserResponse, error)
	Update(ctx context.Context, in *UserRequest, opts ...grpc.CallOption) (*SingleResponse, error)
	Delete(ctx context.Context, in *SingleUserRequest, opts ...grpc.CallOption) (*SingleResponse, error)
	ReadPhoneInfo(ctx context.Context, in *ReadPhoneInfoRequest, opts ...grpc.CallOption) (*ReadPhoneInfoResponse, error)
	AddInfoToTransactions(ctx context.Context, in *AddInfoToTransacionRequest, opts ...grpc.CallOption) (*AddInfoToTransacionResponse, error)
}

type userServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewUserServiceClient(cc grpc.ClientConnInterface) UserServiceClient {
	return &userServiceClient{cc}
}

func (c *userServiceClient) Create(ctx context.Context, in *UserRequest, opts ...grpc.CallOption) (*SingleResponse, error) {
	out := new(SingleResponse)
	err := c.cc.Invoke(ctx, "/grpc.component.com.proto.user.UserService/Create", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *userServiceClient) Read(ctx context.Context, in *SingleUserRequest, opts ...grpc.CallOption) (*UserResponse, error) {
	out := new(UserResponse)
	err := c.cc.Invoke(ctx, "/grpc.component.com.proto.user.UserService/Read", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *userServiceClient) Update(ctx context.Context, in *UserRequest, opts ...grpc.CallOption) (*SingleResponse, error) {
	out := new(SingleResponse)
	err := c.cc.Invoke(ctx, "/grpc.component.com.proto.user.UserService/Update", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *userServiceClient) Delete(ctx context.Context, in *SingleUserRequest, opts ...grpc.CallOption) (*SingleResponse, error) {
	out := new(SingleResponse)
	err := c.cc.Invoke(ctx, "/grpc.component.com.proto.user.UserService/Delete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *userServiceClient) ReadPhoneInfo(ctx context.Context, in *ReadPhoneInfoRequest, opts ...grpc.CallOption) (*ReadPhoneInfoResponse, error) {
	out := new(ReadPhoneInfoResponse)
	err := c.cc.Invoke(ctx, "/grpc.component.com.proto.user.UserService/ReadPhoneInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *userServiceClient) AddInfoToTransactions(ctx context.Context, in *AddInfoToTransacionRequest, opts ...grpc.CallOption) (*AddInfoToTransacionResponse, error) {
	out := new(AddInfoToTransacionResponse)
	err := c.cc.Invoke(ctx, "/grpc.component.com.proto.user.UserService/AddInfoToTransactions", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UserServiceServer is the server API for UserService service.
// All implementations must embed UnimplementedUserServiceServer
// for forward compatibility
type UserServiceServer interface {
	Create(context.Context, *UserRequest) (*SingleResponse, error)
	Read(context.Context, *SingleUserRequest) (*UserResponse, error)
	Update(context.Context, *UserRequest) (*SingleResponse, error)
	Delete(context.Context, *SingleUserRequest) (*SingleResponse, error)
	ReadPhoneInfo(context.Context, *ReadPhoneInfoRequest) (*ReadPhoneInfoResponse, error)
	AddInfoToTransactions(context.Context, *AddInfoToTransacionRequest) (*AddInfoToTransacionResponse, error)
	mustEmbedUnimplementedUserServiceServer()
}

// UnimplementedUserServiceServer must be embedded to have forward compatible implementations.
type UnimplementedUserServiceServer struct {
}

func (UnimplementedUserServiceServer) Create(context.Context, *UserRequest) (*SingleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Create not implemented")
}
func (UnimplementedUserServiceServer) Read(context.Context, *SingleUserRequest) (*UserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Read not implemented")
}
func (UnimplementedUserServiceServer) Update(context.Context, *UserRequest) (*SingleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Update not implemented")
}
func (UnimplementedUserServiceServer) Delete(context.Context, *SingleUserRequest) (*SingleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Delete not implemented")
}
func (UnimplementedUserServiceServer) ReadPhoneInfo(context.Context, *ReadPhoneInfoRequest) (*ReadPhoneInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReadPhoneInfo not implemented")
}
func (UnimplementedUserServiceServer) AddInfoToTransactions(context.Context, *AddInfoToTransacionRequest) (*AddInfoToTransacionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddInfoToTransactions not implemented")
}
func (UnimplementedUserServiceServer) mustEmbedUnimplementedUserServiceServer() {}

// UnsafeUserServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to UserServiceServer will
// result in compilation errors.
type UnsafeUserServiceServer interface {
	mustEmbedUnimplementedUserServiceServer()
}

func RegisterUserServiceServer(s grpc.ServiceRegistrar, srv UserServiceServer) {
	s.RegisterService(&UserService_ServiceDesc, srv)
}

func _UserService_Create_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserServiceServer).Create(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.component.com.proto.user.UserService/Create",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserServiceServer).Create(ctx, req.(*UserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UserService_Read_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SingleUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserServiceServer).Read(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.component.com.proto.user.UserService/Read",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserServiceServer).Read(ctx, req.(*SingleUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UserService_Update_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserServiceServer).Update(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.component.com.proto.user.UserService/Update",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserServiceServer).Update(ctx, req.(*UserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UserService_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SingleUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserServiceServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.component.com.proto.user.UserService/Delete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserServiceServer).Delete(ctx, req.(*SingleUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UserService_ReadPhoneInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReadPhoneInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserServiceServer).ReadPhoneInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.component.com.proto.user.UserService/ReadPhoneInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserServiceServer).ReadPhoneInfo(ctx, req.(*ReadPhoneInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UserService_AddInfoToTransactions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddInfoToTransacionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserServiceServer).AddInfoToTransactions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc.component.com.proto.user.UserService/AddInfoToTransactions",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserServiceServer).AddInfoToTransactions(ctx, req.(*AddInfoToTransacionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// UserService_ServiceDesc is the grpc.ServiceDesc for UserService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var UserService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "grpc.component.com.proto.user.UserService",
	HandlerType: (*UserServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Create",
			Handler:    _UserService_Create_Handler,
		},
		{
			MethodName: "Read",
			Handler:    _UserService_Read_Handler,
		},
		{
			MethodName: "Update",
			Handler:    _UserService_Update_Handler,
		},
		{
			MethodName: "Delete",
			Handler:    _UserService_Delete_Handler,
		},
		{
			MethodName: "ReadPhoneInfo",
			Handler:    _UserService_ReadPhoneInfo_Handler,
		},
		{
			MethodName: "AddInfoToTransactions",
			Handler:    _UserService_AddInfoToTransactions_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "user/user.proto",
}