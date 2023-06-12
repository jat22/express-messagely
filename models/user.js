/** User class for message.ly */

const ExpressError = require("../expressError");
const bcrypt = require("bcrypt");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require('../config');
const db = require('../db');

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) {
    if(!username || !password || !first_name || !last_name || !phone){
      throw new ExpressError('Please enter all required information', 400)
    }
    try{
      const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
      const result = await db.query(`
        INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
        VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
        RETURNING username, password, first_name, last_name, phone`,
        [username, hashedPassword, first_name, last_name, phone])
      const user = result.rows[0];
      return user 
    } catch(e){
      if(e.code === '23505'){
        return new ExpressError('Username is taken. Please select another', 400)
      }
    }

   }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    if(!username || !password){
      throw new ExpressError('Please enter username and password', 400)
    }
    const result = await db.query(`
      SELECT password FROM users
      WHERE username=$1`, [username]);

    const user = result.rows[0];
    if(user){
      if(await bcrypt.compare(password, user.password)){
        return true
      }
      return false
    }
    return false
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(`
      UPDATE users
      SET last_login_at=current_timestamp
      WHERE username=$1`,
      [username])
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(`
      SELECT username, first_name, last_name, phone
      FROM users`)
      return results.rows
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(`
      SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users
      WHERE username=$1`,
      [username]);
    return result.rows[0]
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(`
      SELECT  m.id, 
              m.body, 
              m.sent_at, 
              m.read_at, 
              m.to_username, 
              u.first_name, 
              u.last_name, 
              u.phone
      FROM messages AS m
        JOIN users AS u
        ON u.username = m.to_username
      WHERE m.from_username = $1`,
      [username]);

    const msgs = results.rows.map( m => {
      return {id : m.id,
              body : m.body,
              sent_at : m.sent_at,
              read_at : m.read_at,
              to_user : {
                username : m.to_username,
                first_name : m.first_name,
                last_name : m.last_name,
                phone : m.phone
              }
            };
    });
    return msgs;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(`
      SELECT  m.id,
              m.body,
              m.sent_at,
              m.read_at,
              m.from_username,
              u.first_name,
              u.last_name,
              u.phone
      FROM messages AS m
        JOIN users AS u
        ON u.username = m.from_username
      WHERE m.to_username = $1`,
      [username]
    );

    const msgs = results.rows.map(m => {
      return {
        id : m.id,
        body : m.body,
        sent_at : m.sent_at,
        read_at : m.read_at,
        from_user : {
          username : m.from_username,
          first_name : m.first_name,
          last_name : m.last_name,
          phone : m.phone
        }
      }
    })

    return msgs
  }
}


module.exports = User;