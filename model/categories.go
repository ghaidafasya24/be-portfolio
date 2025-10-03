package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Categories struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"_id,omitempty"`
	CategoryName string             `bson:"category_name,omitempty" json:"category_name,omitempty"`
}
