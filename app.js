const express = require('express')
const path = require('path')
const sqlite3 = require('sqlite3')
const {open} = require('sqlite')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')

const app = express()
app.use(express.json())

const dbPath = path.join(__dirname, 'twitterClone.db')

let db = null
const jwtSecret = 'MY_SECRET_TOKEN'

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })

    app.listen(3000, () => {
      console.log('Server Running at http://localhost:3000/')
    })
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    process.exit(1)
  }
}

initializeDBAndServer()

// API 1: Register
app.post('/register/', async (request, response) => {
  const {username, password, name, gender} = request.body

  const existingUser = await db.get(`SELECT * FROM user WHERE username = ?`, [
    username,
  ])

  if (existingUser !== undefined) {
    response.status(400).send('User already exists')
  } else if (password.length < 6) {
    response.status(400).send('Password is too short')
  } else {
    const hashedPassword = await bcrypt.hash(password, 10)

    await db.run(
      `INSERT INTO user (username, password, name, gender)
       VALUES (?, ?, ?, ?)`,
      [username, hashedPassword, name, gender],
    )

    response.status(200).send('User created successfully')
  }
})

// API 2: Login
app.post('/login/', async (request, response) => {
  const {username, password} = request.body

  const user = await db.get(`SELECT * FROM user WHERE username = ?`, [username])

  if (user === undefined) {
    response.status(400).send('Invalid user')
  } else {
    const isPasswordMatched = await bcrypt.compare(password, user.password)

    if (isPasswordMatched) {
      const payload = {username: username}
      const jwtToken = jwt.sign(payload, jwtSecret)

      response.send({jwtToken})
    } else {
      response.status(400).send('Invalid password')
    }
  }
})

// JWT Authentication Middleware
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers['authorization']
  let jwtToken

  if (authHeader !== undefined) {
    jwtToken = authHeader.split(' ')[1]
  }

  if (jwtToken === undefined) {
    response.status(401).send('Invalid JWT Token')
  } else {
    jwt.verify(jwtToken, jwtSecret, (error, payload) => {
      if (error) {
        response.status(401).send('Invalid JWT Token')
      } else {
        request.username = payload.username
        next()
      }
    })
  }
}

// Helper: Get logged-in user ID
const getUserId = async username => {
  const user = await db.get(`SELECT user_id FROM user WHERE username = ?`, [
    username,
  ])
  return user.user_id
}

// Helper: Check if tweet belongs to a followed user
const isFollowingTweet = async (userId, tweetId) => {
  const tweet = await db.get(
    `SELECT tweet_id
     FROM tweet
     WHERE tweet_id = ?
       AND user_id IN (
         SELECT following_user_id
         FROM follower
         WHERE follower_user_id = ?
       )`,
    [tweetId, userId],
  )

  return tweet !== undefined
}

// API 3: Get latest 4 tweets from followed users
app.get('/user/tweets/feed/', authenticateToken, async (request, response) => {
  const userId = await getUserId(request.username)

  const tweets = await db.all(
    `SELECT user.username AS username,
              tweet.tweet AS tweet,
              tweet.date_time AS dateTime
       FROM tweet
       INNER JOIN user ON tweet.user_id = user.user_id
       WHERE tweet.user_id IN (
         SELECT following_user_id
         FROM follower
         WHERE follower_user_id = ?
       )
       ORDER BY tweet.date_time DESC
       LIMIT 4`,
    [userId],
  )

  response.send(tweets)
})

// API 4: Get people whom the user follows
app.get('/user/following/', authenticateToken, async (request, response) => {
  const userId = await getUserId(request.username)

  const following = await db.all(
    `SELECT user.name AS name
       FROM follower
       INNER JOIN user
         ON follower.following_user_id = user.user_id
       WHERE follower.follower_user_id = ?`,
    [userId],
  )

  response.send(following)
})

// API 5: Get followers of the user
app.get('/user/followers/', authenticateToken, async (request, response) => {
  const userId = await getUserId(request.username)

  const followers = await db.all(
    `SELECT user.name AS name
       FROM follower
       INNER JOIN user
         ON follower.follower_user_id = user.user_id
       WHERE follower.following_user_id = ?`,
    [userId],
  )

  response.send(followers)
})

// API 6: Get a tweet, likes count, replies count, and date-time
app.get('/tweets/:tweetId/', authenticateToken, async (request, response) => {
  const userId = await getUserId(request.username)
  const {tweetId} = request.params

  const validTweet = await isFollowingTweet(userId, tweetId)

  if (!validTweet) {
    response.status(401).send('Invalid Request')
    return
  }

  const tweetDetails = await db.get(
    `SELECT tweet.tweet AS tweet,
              COUNT(DISTINCT like.like_id) AS likes,
              COUNT(DISTINCT reply.reply_id) AS replies,
              tweet.date_time AS dateTime
       FROM tweet
       LEFT JOIN like ON tweet.tweet_id = like.tweet_id
       LEFT JOIN reply ON tweet.tweet_id = reply.tweet_id
       WHERE tweet.tweet_id = ?
       GROUP BY tweet.tweet_id`,
    [tweetId],
  )

  response.send(tweetDetails)
})

// API 7: Get usernames who liked a tweet
app.get(
  '/tweets/:tweetId/likes/',
  authenticateToken,
  async (request, response) => {
    const userId = await getUserId(request.username)
    const {tweetId} = request.params

    const validTweet = await isFollowingTweet(userId, tweetId)

    if (!validTweet) {
      response.status(401).send('Invalid Request')
      return
    }

    const likes = await db.all(
      `SELECT user.username AS username
       FROM like
       INNER JOIN user ON like.user_id = user.user_id
       WHERE like.tweet_id = ?`,
      [tweetId],
    )

    response.send({
      likes: likes.map(item => item.username),
    })
  },
)

// API 8: Get replies for a tweet
app.get(
  '/tweets/:tweetId/replies/',
  authenticateToken,
  async (request, response) => {
    const userId = await getUserId(request.username)
    const {tweetId} = request.params

    const validTweet = await isFollowingTweet(userId, tweetId)

    if (!validTweet) {
      response.status(401).send('Invalid Request')
      return
    }

    const replies = await db.all(
      `SELECT user.name AS name,
              reply.reply AS reply
       FROM reply
       INNER JOIN user ON reply.user_id = user.user_id
       WHERE reply.tweet_id = ?`,
      [tweetId],
    )

    response.send({replies})
  },
)

// API 9: Get all tweets of the logged-in user
app.get('/user/tweets/', authenticateToken, async (request, response) => {
  const userId = await getUserId(request.username)

  const tweets = await db.all(
    `SELECT tweet.tweet AS tweet,
              COUNT(DISTINCT like.like_id) AS likes,
              COUNT(DISTINCT reply.reply_id) AS replies,
              tweet.date_time AS dateTime
       FROM tweet
       LEFT JOIN like ON tweet.tweet_id = like.tweet_id
       LEFT JOIN reply ON tweet.tweet_id = reply.tweet_id
       WHERE tweet.user_id = ?
       GROUP BY tweet.tweet_id
       ORDER BY tweet.date_time DESC`,
    [userId],
  )

  response.send(tweets)
})

// API 10: Create a tweet
app.post('/user/tweets/', authenticateToken, async (request, response) => {
  const userId = await getUserId(request.username)
  const {tweet} = request.body

  await db.run(
    `INSERT INTO tweet (tweet, user_id, date_time)
       VALUES (?, ?, datetime('now'))`,
    [tweet, userId],
  )

  response.send('Created a Tweet')
})

// API 11: Delete a tweet
app.delete(
  '/tweets/:tweetId/',
  authenticateToken,
  async (request, response) => {
    const userId = await getUserId(request.username)
    const {tweetId} = request.params

    const tweet = await db.get(`SELECT * FROM tweet WHERE tweet_id = ?`, [
      tweetId,
    ])

    if (tweet === undefined || tweet.user_id !== userId) {
      response.status(401).send('Invalid Request')
    } else {
      // Remove dependent records before deleting the tweet
      await db.run(`DELETE FROM like WHERE tweet_id = ?`, [tweetId])
      await db.run(`DELETE FROM reply WHERE tweet_id = ?`, [tweetId])
      await db.run(`DELETE FROM tweet WHERE tweet_id = ?`, [tweetId])

      response.send('Tweet Removed')
    }
  },
)

module.exports = app
