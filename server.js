const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt-nodejs');
const cors = require('cors');
const knex = require('knex');
const jwt = require('jsonwebtoken');

const db = knex({
    client: 'pg',
    connection: {
        connectionString: process.env.DATABASE_URL,
        ssl: true,
    }
})

let entries = 0;

const app = express();

const parseToken = (req, res, next) => {
    const bearerHeader = req.headers['authorization'];
    if(bearerHeader) {
        const bearer = bearerHeader.split(' ');
        const bearerToken = bearer[1];
        req.token = bearerToken;
        next();
    } else {
        res.sendStatus(403);
    }
}

app.use(bodyParser.json());
app.use(cors()); //for unsecure requests. just to test the app on a localhsot

app.get('/', (req, res) => {
    entries ++;
    res.end(`<h1>${entries}</h1>`);
})

app.post('/signin', (req, res) => {
    db.select('loginemail', 'hash').from('login').where('loginemail', '=', req.body.email)
    .then(data => {
        const isValid = bcrypt.compareSync(req.body.password, data[0].hash);
        if (isValid) {
            return db.select('*').from('customers').where('email', '=', req.body.email)
            .then(async user => {
                const passengers = await db.select('*').from('passengers').where('customer_id', '=', user[0].id);
                const trips = await db.select('*').from('trips').where('owner_id', '=', user[0].id);
                jwt.sign({customer: user[0]}, 'customerportal', (err, token) => {
                    res.json({
                        token,
                        customer: user[0],
                        passengers,
                        trips
                    })
                })
            })
            .catch(err => res.status(400).json('unable to get user'))
        } else {
            res.status(400).json('wrong credentials')
        }
    })
    .catch(err => res.status(400).json('wrong credentials'))
})

app.get('/auth', parseToken, (req, res) => {
    jwt.verify(req.token, 'customerportal', (err, authData) => {
        if(err) {
            res.sendStatus(403);
        } else {
            db.select('*').from('customers').where('email', '=', authData.customer.email)
            .then(async user => {
                const passengers = await db.select('*').from('passengers').where('customer_id', '=', user[0].id);
                const trips = await db.select('*').from('trips').where('owner_id', '=', user[0].id);
                res.json({
                    customer: user[0],
                    passengers,
                    trips
                })
            })
            .catch(err => res.status(400).json('unable to get user'))
        }
    })
})

app.put('/customers', parseToken, (req, res) => {
    jwt.verify(req.token, 'customerportal', (err, authData) => {
        if(err) {
            res.sendStatus(403);
        } else {
            db('customers').update(req.body).where('id', '=', authData.customer.id)
            .catch((err) => res.status(400).json('Unable to update'))
            .then(res.json(req.body));
        }
    })
})

app.post('/passengers', parseToken, (req, res) => {
    jwt.verify(req.token, 'customerportal', (err, authData) => {
        if(err) {
            res.sendStatus(403);
        } else {
            const { title, firstname, surname, passportid } = req.body;
            if(!title || !firstname || !surname || !passportid) {
                res.status(400).json('Invalid request')
            } else {
                db.insert({
                    title,
                    firstname,
                    surname,
                    passportid,
                    customer_id: authData.customer.id
                }).into('passengers').returning('*')
                .then(passenger => res.json(passenger))
                .catch(err => res.json('Unable to add passenger'))
            }
        }
    })
})

app.delete('/passengers', parseToken, (req, res) => {
    jwt.verify(req.token, 'customerportal', (err, authData) => {
        if(err) {
            res.sendStatus(403);
        } else if(req.body.id){
            db.delete().from('passengers').where('passengerid', '=', req.body.id)
            .then(res.json('Success'))
            .catch(err => res.status(400).json('Unable to delete passenger'))
        } else {
            res.status(400).json('Invalid request');
        }
    })
})

app.post('/trips', parseToken, (req, res) => {
    jwt.verify(req.token, 'customerportal', (err, authData) => {
        if(err) {
            res.sendStatus(403);
        } else {
            const { departure_airport, destination_airport, departure_time, arrival_time, passengers } = req.body;
            if(!departure_airport || !destination_airport || !departure_time || !arrival_time || !passengers || arrival_time < departure_time) {
                res.status(400).json('Invalid request');
            } else {
                db.insert({
                    owner_id: authData.customer.id,
                    departure_airport,
                    destination_airport,
                    departure_time,
                    arrival_time,
                    passengers
                }).into('trips').returning('*')
                .then(trip => res.json(trip))
                .catch(err => res.json('Unable to add trip'))
            }
        }
    })
})

app.delete('/trips', parseToken, (req, res) => {
    jwt.verify(req.token, 'customerportal', (err, authData) => {
        if(err) {
            res.sendStatus(403);
        } else if(req.body.trip_id){
            db.delete().from('trips').where('trip_id', '=', req.body.trip_id)
            .then(res.json('Success'))
            .catch(err => res.status(400).json('Unable to delete trip'))
        } else {
            res.status(400).json('Invalid request');
        }
    })
})

app.listen(process.env.PORT || 3001, () => {
    console.log(`app is running on port ${process.env.PORT}`);
})