package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Certificates struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"_id,omitempty"`
	Title         string             `bson:"title,omitempty" json:"title,omitempty"`
	Image         string             `bson:"image,omitempty" json:"image,omitempty"`
	Description   string             `bson:"description,omitempty" json:"description,omitempty"`
	Provided      string             `bson:"provided,omitempty" json:"provided,omitempty"`
	YearPublished string             `bson:"year_published,omitempty" json:"year_published,omitempty"`
	Categories    Categories         `bson:"categories,omitempty" json:"categories,omitempty"`
	CreatedAt     time.Time          `bson:"created_at,omitempty" json:"created_at,omitempty"` // Field baru untuk waktu
}
