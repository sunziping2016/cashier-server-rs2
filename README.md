## 1 Model Design

### 1.1 Permissions

A permission represents the ability to do one action. If a user has a role (including `default` role), and this role contains a permission, then we say this user has this permission.

|Key|Type|Description|
|---|---|---|
|subject|String|the subject of the permission|
|action|String|the action of the permission|
|display_name|String|a name for display purpose|
|description|String|a more detailed explanation|
|created_at|Date|the time to create the permission|
|updated_at|Date|last time to update the permission|
|deleted|Boolean|whether the permission is deleted|

All fields are required.

### 1.2 Roles

A role consists of several mutually related permissions.

|Key|Type|Description|
|---|---|---|
|name|String|the name of the role|
|permissions|Array\<ObjectId\>|permissions of the role|
|display_name|String|a name for display purpose|
|description|String|a more detailed explanation|
|created_at|Date|the time to create the role|
|updated_at|Date|last time to update the role|
|deleted|Boolean|whether the role is deleted|

All fields are required.

### 1.3 Users

|Key|Type|Description|Required|Public|
|---|---|---|---|---|
|username|String|the username of the user|true|true|
|password|String|the password of the user|true|false|
|roles|Array\<ObjectId\>|the roles of the user|true|false|
|email|String|the email of the user|false|false|
|nickname|String|the nickname of the user|false|true|
|avatar|String|path to the avatar|false|true|
|avatar128|String|path to a square 128x128 avatar|false|true|
|blocked|Boolean|whether the user is blocked|false|false|
|created_at|Date|the time to create the user|true|true|
|updated_at|Date|last time to update the user|true|false|
|deleted|Boolean|whether the user is deleted|true|false|

User's public information can be accessed via `/api/v1/users/public`. `password` is never accessible.

`username` and `email` should be unique.

### 1.4 Tokens

|Key|Type|Description|
|---|---|---|
|user|ObjectId|user who owns the token|
|issued_at|Date|the time to create the token|
|expires_at|Date|the time when the token expires|
|acquire_method|String|method to acquire the token|
|invoked|bool|whether jwt is invoked|

All fields are required.

### 1.5 Global Settings

There should exists one single document in `globalSettings` document.

|Key|Type|Description|
|---|---|---|
|jwt_secret|Binary|256-byte random secret for JWT|
|created_at|Date|the time to create the global settings|
|updated_at|Date|last time to update the global settings|

All fields are required.

### 1.6 User Registration

|Key|Type|Description|
|---|---|---|
|id|String|24-byte randomly generated token|
|code|String|6-byte randomly generated digital code|
|username|String|the username of the user|
|password|String|the password of the user|
|email|String|the email of the user|
|created_at|Date|the time to create the user|
|expires_at|Date|last time to update the user|
|completed|Boolean|`null` for not completed, `false` for rejected, `true` for completed|

### 1.7 User Email Updating

|Key|Type|Description|
|---|---|---|
|id|String|24-byte randomly generated token|
|code|String|6-byte randomly generated digital code|
|user|Integer|the id of the user|
|new_email|String|the new email of the user|
|created_at|Date|the time to create the user|
|expires_at|Date|last time to update the user|
|completed|Boolean|`null` for not completed, `false` for rejected, `true` for completed|

## 2 TODO

- [x] Multipart
- [x] WebSocket
- [ ] Captcha

## 3 WebSocket实现

每个服务器启动的时候会启动一个actor（ServerSubscriber）。该actor需要位于可被获取web::Data中，而后被处理WebSocket的Handler获取，并且它支持向其添加和删除订阅的消息以及ClientSubscriber（因而是个HashMap<String, HashSet<_>>，String是subject）。该actor启动的时候，会创建一个异步死循环，从redis中读取订阅的消息。

消息的格式为JSON。消息支持serialize和deserialize，目前考虑置于messages目录下。最后发送的消息是个集合所有可能消息的大Enum。除此之外，传送的数据还有subject，以及可选的发起uid，发起jti。

每个WebSocket连接会启动一个actor（ClientSubscriber），该actor会向ServerSubscriber注册自己。而后当它收到消息的时候就会推送到客户端。此外它还会每隔一段时间发送心跳（30s），如果客户端没有响应心跳超过一段时间就断开连接（1min）。此外当jwt expires的时候，也会断开连接。

权限管理方面，每个用户的监听权限，就是那些action为subscribe的权限。这些权限的subject在启动ClientSubscriber时被搜集起来并且提交给ServerSubscriber。如果某个subject的后缀是`-self`，那么这部分会被删除。每个ClientSubscriber会存储当前监听的subject列表，和jwt claims，中间包含uid和jti。如果收到消息有对应subject或者(有带`{subject}-self`且uid与消息中的uid符合，这里消息的uid)，那么这个消息会被发送出去，其他情况下消息就会被忽略，消息中的subject，uid和jti都发布给客户端。

客户端遇到自己的WebSocket传来的数据是自己的jti的时候可以适当去重。

jwt如果被revoke，user如果被删除或block，ClientSubscriber收到这个消息都会断开连接。如果user的roles发生变更，user.roles中的一个role的permissions发生变更，对应的ClientSubscriber都会更新权限。注意：删除一个被role引用的permission和删除一个被user引用的role是不被允许的。

需要提供一个简单的函数，供所有的API发起消息到redis中，并附带上uid和jti数据。

未来考虑添加一个额外的表：用户<->监听的用户权限。第二个键cascade删除。然后实现用户选择收到某个推送。

## 4 用户注册流程

提供API查询用户名或密码是否被占用。如果被占用则报错。通过验证后，生成随机的长度为40的ID串以及6位数字密码。发送邮件给用户，其中邮件包含数字密码。邮件发送成功后，写入临时用户表，`completed`为`null`。而后id返回给前端。验证时，将id和验证码POST到后端，后端从`completed`为`null`，id为指定id的临时用户表中读取数据，确认是否expire，确认验证码是否正确，，再次确认用户名和密码是否被占用，如果成功后创建用户，并且置`completed`为true，这部分需要repeated read隔离等级。