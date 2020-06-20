## 1 Model Design

### 1.1 Permissions

A permission represents the ability to do one action. If a user has a role (including `default` role), and this role contains a permission, then we say this user has this permission.

|Key|Type|Description|
|---|---|---|
|subject|String|the subject of the permission|
|action|String|the action of the permission|
|displayName|String|a name for display purpose|
|description|String|a more detailed explanation|
|createdAt|Date|the time to create the permission|
|updatedAt|Date|last time to update the permission|
|deleted|Boolean|whether the permission is deleted|

All fields are required.

### 1.2 Roles

A role consists of several mutually related permissions.

|Key|Type|Description|
|---|---|---|
|name|String|the name of the role|
|permissions|Array\<ObjectId\>|permissions of the role|
|displayName|String|a name for display purpose|
|description|String|a more detailed explanation|
|createdAt|Date|the time to create the role|
|updatedAt|Date|last time to update the role|
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
|createdAt|Date|the time to create the user|true|true|
|updatedAt|Date|last time to update the user|true|false|
|deleted|Boolean|whether the user is deleted|true|false|

User's public information can be accessed via `/api/v1/users/public`. `password` is never accessible.

`username` and `email` should be unique.

### 1.4 Tokens

|Key|Type|Description|
|---|---|---|
|user|ObjectId|user who owns the token|
|issuedAt|Date|the time to create the token|
|expiresAt|Date|the time when the token expires|
|acquireMethod|String|method to acquire the token|
|invoked|bool|whether jwt is invoked|

All fields are required.

### 1.5 Global Settings

There should exists one single document in `globalSettings` document.

|Key|Type|Description|
|---|---|---|
|jwtSecret|Binary|256-byte random secret for JWT|
|createdAt|Date|the time to create the global settings|
|updatedAt|Date|last time to update the global settings|

All fields are required.

## 2 TODO

- [x] Multipart
- [ ] WebSocket
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