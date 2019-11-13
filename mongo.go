package mongo

import (
	"context"
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/models"
)

const (
	namespaceExistsErrCode int32 = 48
)


// IndexKey holds a key of index
type IndexKey struct {
	Key  string
	Desc bool
}

// Index reprsents a mongodb index
type Index struct {
	Keys               []IndexKey
	Name               string
	Unique             bool
	Sparse             bool
	ExpireAfterSeconds *int32
}

// Config mongodb configuration parameters
type Config struct {
	ctx context.Context
	URL string
	DB  string
}

// NewConfig create mongodb configuration
func NewConfig(ctx context.Context, url, db string) *Config {
	return &Config{
		ctx: ctx,
		URL: url,
		DB:  db,
	}
}

// TokenConfig token configuration parameters
type TokenConfig struct {
	// store txn collection name(The default is oauth2)
	TxnCName string
	// store token based data collection name(The default is oauth2_basic)
	BasicCName string
	// store access token data collection name(The default is oauth2_access)
	AccessCName string
	// store refresh token data collection name(The default is oauth2_refresh)
	RefreshCName string
}

// NewDefaultTokenConfig create a default token configuration
func NewDefaultTokenConfig() *TokenConfig {
	return &TokenConfig{
		TxnCName:     "oauth2_txn",
		BasicCName:   "oauth2_basic",
		AccessCName:  "oauth2_access",
		RefreshCName: "oauth2_refresh",
	}
}

// NewTokenStore create a token store instance based on mongodb
func NewTokenStore(cfg *Config, tcfgs ...*TokenConfig) (store *TokenStore) {
	opts := options.Client().
		ApplyURI(cfg.URL).
		SetConnectTimeout(10 * time.Second)
	client, err := mongo.Connect(cfg.ctx, opts)
	if err != nil {
		panic(err)
	}

	return NewTokenStoreWithClient(cfg.ctx, client, cfg.DB, tcfgs...)
}

// NewTokenStoreWithClient create a token store instance based on mongodb
func NewTokenStoreWithClient(ctx context.Context, client *mongo.Client, dbName string, tcfgs ...*TokenConfig) (store *TokenStore) {
	ts := &TokenStore{
		dbName: dbName,
		client: client,
		tcfg:   NewDefaultTokenConfig(),
	}
	if len(tcfgs) > 0 {
		ts.tcfg = tcfgs[0]
	}
	var ttl int32 = 60 * 1 // time.Second * 1
	opts := &options.IndexOptions{
		Name:               stringP("expire_after"),
		Unique:             boolP(false),
		Sparse:             boolP(false),
		ExpireAfterSeconds: &ttl,
	}
	expiredModel := mongo.IndexModel{
		Keys:    bson.D{bson.E{"ExpiredAt", false}},
		Options: opts,
	}

	ts.ensureIndex(ctx, ts.tcfg.BasicCName, expiredModel)
	ts.ensureIndex(ctx, ts.tcfg.AccessCName, expiredModel)
	ts.ensureIndex(ctx, ts.tcfg.RefreshCName, expiredModel)

	store = ts
	return
}

func stringP(s string) *string {
	return &s
}

func boolP(b bool) *bool {
	return &b
}

// TokenStore MongoDB storage for OAuth 2.0
type TokenStore struct {
	tcfg   *TokenConfig
	dbName string
	client *mongo.Client
}

// Close close the mongo session
func (ts *TokenStore) Close() {
	ts.Close()
}

func (ts *TokenStore) ensureIndex(ctx context.Context, col string, index mongo.IndexModel) error  {
	cmd := bson.D{{"create", col}}
	if err := ts.client.Database(ts.dbName).RunCommand(ctx, cmd).Err(); err != nil {
		// ignore NamespaceExists errors for idempotency
		cmdErr, ok := err.(mongo.CommandError)
		if !ok || cmdErr.Code != namespaceExistsErrCode {
			return err
		}
	}
	_, err := ts.c(col).Indexes().CreateOne(ctx, index)
	return err
}

func (ts *TokenStore) c(name string) *mongo.Collection {
	return ts.client.Database(ts.dbName).Collection(name)
}

func (ts *TokenStore) cHandler(name string, handler func(c *mongo.Collection) error) error {
	return handler(ts.client.Database(ts.dbName).Collection(name))
}

// Create create and store the new token information
func (ts *TokenStore) Create(info oauth2.TokenInfo) error {
	jv, err := json.Marshal(info)
	if err != nil {
		return err
	}

	ctx := context.Background()

	if code := info.GetCode(); code != "" {
		oid, err := primitive.ObjectIDFromHex(code)
		if err != nil {
			return err
		}
		return ts.cHandler(ts.tcfg.BasicCName, func(c *mongo.Collection) error {
			_, err = c.InsertOne(ctx, basicData{
				ID:        oid,
				Data:      jv,
				ExpiredAt: info.GetCodeCreateAt().Add(info.GetCodeExpiresIn()),
			})
			return err
		})
	}

	aexp := info.GetAccessCreateAt().Add(info.GetAccessExpiresIn())
	rexp := aexp
	if refresh := info.GetRefresh(); refresh != "" {
		rexp = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn())
		if aexp.Second() > rexp.Second() {
			aexp = rexp
		}
	}
	id := primitive.NewObjectID()

	session, err := ts.client.StartSession()
	if err != nil {
		return err
	}
	if err := session.StartTransaction(); err != nil {
		return err
	}

	if err = mongo.WithSession(ctx, session, func(sessionContext mongo.SessionContext) error {
		basicCName := basicData{
			ID:        id,
			Data:      jv,
			ExpiredAt: rexp,
		}
		if err = ts.cHandler(ts.tcfg.BasicCName, func(c *mongo.Collection) error {
			_, err = c.InsertOne(sessionContext, basicCName)
			return err
		}); err != nil {
			return err
		}

		access := info.GetAccess()
		aId, err := primitive.ObjectIDFromHex(access)
		if err != nil {
			return err
		}
		accessCName := tokenData{
			ID:        aId,
			BasicID:   id.Hex(),
			ExpiredAt: aexp,
		}
		if err = ts.cHandler(ts.tcfg.BasicCName, func(c *mongo.Collection) error {
			_, err = c.InsertOne(sessionContext, accessCName)
			return err
		}); err != nil {
			return err
		}

		if refresh := info.GetRefresh(); refresh != "" {
			rId, err := primitive.ObjectIDFromHex(refresh)
			if err != nil {
				return err
			}
			refreshCName := tokenData{
				ID:        rId,
				BasicID:   id.Hex(),
				ExpiredAt: rexp,
			}
			if err = ts.cHandler(ts.tcfg.BasicCName, func(c *mongo.Collection) error {
				_, err = c.InsertOne(sessionContext, refreshCName)
				return err
			}); err != nil {
				return err
			}

		}

		return session.CommitTransaction(sessionContext)
	}); err != nil {
		return err
	}
	session.EndSession(ctx)

	return nil
}

// RemoveByCode use the authorization code to delete the token information
func (ts *TokenStore) RemoveByCode(code string) error {
	return ts.cHandler(ts.tcfg.BasicCName, func(c *mongo.Collection) error {
		q := bson.M{"_id": code}
		_, verr := c.DeleteOne(context.Background(), q)
		if verr != nil {
			if verr == mongo.ErrNoDocuments {
				return nil
			}
		}
		return verr
	})
}

// RemoveByAccess use the access token to delete the token information
func (ts *TokenStore) RemoveByAccess(access string) error {
	return ts.cHandler(ts.tcfg.AccessCName, func(c *mongo.Collection) error {
		q := bson.M{"_id": access}
		_, verr := c.DeleteOne(context.Background(), q)
		if verr != nil {
			if verr == mongo.ErrNoDocuments {
				return nil
			}
		}
		return verr
	})
}

// RemoveByRefresh use the refresh token to delete the token information
func (ts *TokenStore) RemoveByRefresh(refresh string) error {
	return ts.cHandler(ts.tcfg.RefreshCName, func(c *mongo.Collection) error {
		q := bson.M{"_id": refresh}
		_, verr := c.DeleteOne(context.Background(), q)
		if verr != nil {
			if verr == mongo.ErrNoDocuments {
				return nil
			}

		}
		return verr
	})
}

func (ts *TokenStore) getData(basicID string) (ti oauth2.TokenInfo, err error) {
	err = ts.cHandler(ts.tcfg.BasicCName, func(c *mongo.Collection) error {
		var bd basicData
		q := bson.M{"_id": basicID}
		verr := c.FindOne(context.Background(), q).Decode(&bd)
		if verr != nil {
			if verr == mongo.ErrNoDocuments {
				return nil
			}
			return verr
		}
		var tm models.Token
		if err = json.Unmarshal(bd.Data, &tm); err != nil {
			return err
		}
		ti = &tm
		return nil
	})
	return
}

func (ts *TokenStore) getBasicID(cname, token string) (basicID string, err error) {
	err = ts.cHandler(cname, func(c *mongo.Collection) error {
		var td tokenData
		q := bson.M{"_id": token}
		verr := c.FindOne(context.Background(), q).Decode(&td)
		if verr != nil {
			if verr == mongo.ErrNoDocuments {
				return nil
			}
			return verr
		}
		basicID = td.BasicID
		return nil
	})
	return
}

// GetByCode use the authorization code for token information data
func (ts *TokenStore) GetByCode(code string) (ti oauth2.TokenInfo, err error) {
	ti, err = ts.getData(code)
	return
}

// GetByAccess use the access token for token information data
func (ts *TokenStore) GetByAccess(access string) (ti oauth2.TokenInfo, err error) {
	basicID, err := ts.getBasicID(ts.tcfg.AccessCName, access)
	if err != nil && basicID == "" {
		return
	}
	ti, err = ts.getData(basicID)
	return
}

// GetByRefresh use the refresh token for token information data
func (ts *TokenStore) GetByRefresh(refresh string) (ti oauth2.TokenInfo, err error) {
	basicID, err := ts.getBasicID(ts.tcfg.RefreshCName, refresh)
	if err != nil && basicID == "" {
		return
	}
	ti, err = ts.getData(basicID)
	return
}

type basicData struct {
	ID        primitive.ObjectID `bson:"_id"`
	Data      []byte             `bson:"Data"`
	ExpiredAt time.Time          `bson:"ExpiredAt"`
}

type tokenData struct {
	ID        primitive.ObjectID `bson:"_id"`
	BasicID   string             `bson:"BasicID"`
	ExpiredAt time.Time          `bson:"ExpiredAt"`
}
