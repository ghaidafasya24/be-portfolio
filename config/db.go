package config

import (
	"os"

	"github.com/aiteung/atdb"

)

var IteungIPAddress string = os.Getenv("ITEUNGBEV1")

var MongoString string = os.Getenv("MONGOSTRING")

var DBUlbimongoinfo = atdb.DBInfo{
	DBString: MongoString,
	DBName:   "portfolio",
}

var Ulbimongoconn = atdb.MongoConnect(DBUlbimongoinfo)