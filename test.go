package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"

	//import jwt middleware

	"go.mongodb.org/mongo-driver/mongo/options"
)

//the following ate the class descriptions

// Class User :
// 	Parameters type String( name,phone,type,password,email)

// Class Login :
// 	Parameters type String(email,password)

// Class Batches :
// 	Parameters type String(name,description,status,startdate,enddate)
// 	Parameters type Array(files,members)

//create the above classes
var secret = "supersecreteyonlyiknowof"

type User struct {
	Name     string `bson:"name"`
	Phone    string `bson:"phone"`
	Type     string `bson:"type"`
	Password string `bson:"password"`
	Email    string `bson:"email"`
}
type Login struct {
	Email    string `bson:"email"`
	Password string `bson:"password"`
}
type Batches struct {
	Name        string   `bson:"name"`
	Description string   `bson:"description"`
	Status      string   `bson:"status"`
	Startdate   string   `bson:"startdate"`
	Enddate     string   `bson:"enddate"`
	Files       []string `bson:"files"`
	Members     []string `bson:"members"`
}

type ListBatches struct {
	Id          string   `bson:"_id"`
	Name        string   `bson:"name"`
	Description string   `bson:"description"`
	Status      string   `bson:"status"`
	Startdate   string   `bson:"startdate"`
	Enddate     string   `bson:"enddate"`
	Files       []string `bson:"files"`
	Members     []string `bson:"members"`
}

// the following are echo api en points

// endpoint : "/login"
// method : "POST"
// description: endpoint takes parameter of type Login and returns a token

// endpoint :"/signup"
// method : "POST"
// description: endpoint takes parameter of type User and returns a success/error message

// endpoint :"/createbatch"
// method : "POST"
// description: endpoint takes parameter of type Batches and returns a success/error message

//write a main function and implement echo api endpoints
//authgroup
func decodeandverify(token string, typ string) (error, bool) {
	claims := jwt.MapClaims{}
	tokendecoded, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return err, false
	}
	if !tokendecoded.Valid {
		return nil, false
	}
	if tokendecoded.Claims.(jwt.MapClaims)["type"] != typ {
		return nil, false
	}
	return nil, true
}

func main() {

	//new echo instance
	e := echo.New()

	//create a database connection
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		panic(err)
	}
	err = client.Connect(context.TODO())
	if err != nil {
		panic(err)
	}

	//implement api endpoints
	e.POST("/login", func(c echo.Context) error {
		//get the login parameters
		login := new(Login)
		if err := c.Bind(login); err != nil {
			return c.JSON(http.StatusBadRequest, err.Error())
		}

		//print email and password
		fmt.Println(login.Email)
		fmt.Println(login.Password)

		//find the user in the database
		collection := client.Database("lmsbackend").Collection("Users")
		var user User
		err = collection.FindOne(context.TODO(), bson.M{"email": login.Email}).Decode(&user)
		if err != nil {
			return c.JSON(http.StatusOK, map[string]string{
				"error": "User not found",
			})
		}

		//check if the password matches bcrypt hashed password
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(login.Password)); err != nil {
			//print error
			fmt.Println(err)

			return err
		} else {
			//if the password matches return a token
			token := jwt.New(jwt.SigningMethodHS256)
			claims := token.Claims.(jwt.MapClaims)
			claims["email"] = user.Email
			claims["type"] = user.Type
			tokenString, err := token.SignedString([]byte(secret))
			if err != nil {
				return err
			}

			//auth check
			// e1, v1 := decodeandverify(tokenString, "student")
			// if e1 == nil {
			// 	fmt.Println(v1)
			// }
			return c.JSON(http.StatusOK, map[string]string{
				"token": tokenString,
			})
		}

	})

	//implement signup endpoint
	e.POST("/signup", func(c echo.Context) error {
		//get the user parameters
		user := new(User)
		err := c.Bind(user)
		if err != nil {
			return c.JSON(http.StatusBadRequest, err.Error())
		}
		//check if user already exists
		collection := client.Database("lmsbackend").Collection("Users")
		var user1 User
		err = collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&user1)
		if err != nil {
			//inser the user into the database
			//hash the password
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
			if err != nil {
				return c.JSON(http.StatusBadRequest, err.Error())
			}
			user.Password = string(hashedPassword)
			_, err = collection.InsertOne(context.TODO(), user)
			if err != nil {
				return c.JSON(http.StatusBadRequest, err.Error())
			}
			return c.JSON(http.StatusOK, map[string]string{
				"message": "User created",
			})
		} else {
			return c.JSON(http.StatusOK, map[string]string{
				"error": "User already exists",
			})
		}
	})

	//api route to create a batch
	e.POST("/createbatch", func(c echo.Context) error {
		//get the batch parameters
		batch := new(Batches)
		err := c.Bind(batch)
		if err != nil {
			return c.JSON(http.StatusBadRequest, err.Error())
		}
		//check if batch already exists
		collection := client.Database("lmsbackend").Collection("Batches")
		var batch1 Batches
		err = collection.FindOne(context.TODO(), bson.M{"name": batch.Name}).Decode(&batch1)
		if err != nil {
			//inser the batch into the database
			_, err = collection.InsertOne(context.TODO(), batch)
			if err != nil {
				return c.JSON(http.StatusBadRequest, err.Error())
			}
			return c.JSON(http.StatusOK, map[string]string{
				"message": "Batch created",
			})
		} else {
			return c.JSON(http.StatusOK, map[string]string{
				"error": "Batch already exists",
			})
		}
	})

	//api endpoint for getting all batches
	e.GET("/getbatches", func(c echo.Context) error {
		collection := client.Database("lmsbackend").Collection("Batches")
		cur, err := collection.Find(context.TODO(), bson.D{})
		if err != nil {
			return c.JSON(http.StatusBadRequest, err.Error())
		}
		var batches []Batches
		for cur.Next(context.TODO()) {
			var batch Batches
			err := cur.Decode(&batch)
			if err != nil {
				return c.JSON(http.StatusBadRequest, err.Error())
			}
			batches = append(batches, batch)
		}
		return c.JSON(http.StatusOK, batches)
	})

	//enable recoveery and hot reload
	e.Pre(middleware.Recover())
	//start the sever on port 80
	e.Logger.Fatal(e.Start(":80"))

}
