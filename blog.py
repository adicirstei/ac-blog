import os
import webapp2
import jinja2

from google.appengine.ext import db
from google.appengine.api import memcache
import time
import random
import string
import hashlib
import logging
import json



def make_salt():
  return ''.join(random.choice(string.letters) for x in xrange(5))

# Implement the function valid_pw() that returns True if a user's password 
# matches its hash. You will need to modify make_pw_hash.

def make_pw_hash(name, pw, salt): 
  h = hashlib.sha256(name + pw + salt).hexdigest()
  return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
  s = h.split('|')[1]
  return make_pw_hash(name, pw, s) == h

# print valid_pw('spez', 'hunter21', h)


def hash_str(s):
  return hashlib.md5(s).hexdigest()

def make_secure_val(s):
  return "%s|%s" % (s, hash_str(s))

# -----------------
# User Instructions
# 
# Implement the function check_secure_val, which takes a string of the format 
# s,HASH
# and returns s if hash_str(s) == HASH, otherwise None 

def check_secure_val(h):
  ###Your code here
  t = h.split('|')
  if hash_str(t[0]) == t[1]:
    return t[0]
  else:
    return None

class BlogPostEncoder(json.JSONEncoder):
  def default(self, obj):
    if isinstance(obj, BlogPost):
      return {'content': obj.content, 'subject': obj.subject, 'created': obj.created.strftime('%c')}
    return json.JSONEncoder.default(self, obj)

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape= True)

class Handler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)
  def render_str(self, template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))

class BlogPost(db.Model):
  subject = db.StringProperty(required = True)
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty(auto_now_add = True)
  
class User(db.Model):
  username = db.StringProperty(required = True)
  password_hash = db.StringProperty(required = True)
  email = db.StringProperty(required = False)
  created = db.DateTimeProperty(auto_now_add = True)  
  
def get_post(id, update = False):
  key = 'post' + str(id)
  post = memcache.get(key)
  if update or post is None:
    post = BlogPost.get_by_id(long(id))    

    memcache.set(key, post)

    memcache.set("age"+str(id), time.time())
  return post
  
def get_front(update = False):
  key = 'posts'
  posts = memcache.get(key)
  if update or posts is None:
    posts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC LIMIT 10")
    posts = list(posts)
    memcache.set(key, posts)

    memcache.set("age", time.time())
  return posts

class MainPage(Handler):
  def render_front(self):
    posts = get_front()
    age = time.time() - memcache.get("age")
    self.render("front.html", posts = posts, age = 'Queried %d seconds ago' % age)

  def json_front(self):
    posts = get_front()

    self.response.headers["Content-Type"] = "application/json"
    lp = [BlogPostEncoder().encode(p) for p in posts]

    j = json.dumps([json.loads(p) for p in lp])

    self.response.write(j)
    
  def get(self, format):
    if format and format == '.json':
      self.json_front()
      return
    self.render_front()
    
class SignUp(Handler):
    
  def get(self):
  
    self.render("signup.html")
    
  def post(self):
    # self.request.cookies.get(name)
    # self.response.headers.add_header('Set-Cookie', 'name=value; Path=/')
    
    username = self.request.get("username")
    password = self.request.get("password")
    verify = self.request.get("verify")
    email = self.request.get("email")

    
    users = db.GqlQuery("SELECT * FROM User where username = :1", username)
    if users.count() > 0:

      error = "user already exists. pick another! id: %d" % users.get().key().id()
      self.render("signup.html", username=username, email=email, error=error)
      return
    
      
    if username and password and password == verify:
      password_hash = make_pw_hash(username, password, make_salt())
    
      u = User(username=username, password_hash=password_hash, email=email)
      u.put()
      
      userid = u.key().id()
      
      self.response.headers.add_header('Set-Cookie', 'user_id='+ make_secure_val(str(userid)) +'; Path=/')
      self.redirect("/welcome")
    else:
      error = "you need to type a username and the password to match!"
      self.render("signup.html", username=username, email=email, error=error)
class Logout(Handler):
  def get(self):
    self.response.headers.add_header('Set-Cookie', 'user_id= ; Path=/')
    self.redirect("/signup")
    
class Login(Handler):
    
  def get(self):
    logging.debug('booooooo')
    self.render("login.html")
    
  def post(self):
    
    username = self.request.get("username")
    password = self.request.get("password")

    user = db.GqlQuery("SELECT * FROM User where username = :1", username).get()
    
    if user and valid_pw(username, password, user.password_hash):
      userid = user.key().id()
      self.response.headers.add_header('Set-Cookie', 'user_id='+ make_secure_val(str(userid)) +'; Path=/')
      self.redirect("/welcome")

    else:
      error = "wrong username or password!"
      self.render("login.html", username=username, error=error)      
      
class Welcome(Handler):
    
  def get(self):
    userid = self.request.cookies.get('user_id')

    if userid:
      uid = check_secure_val(userid)
      if uid:
        user = User.get_by_id(long(uid))
        self.render("welcome.html", username=user.username)
      else:
        self.redirect("/signup")
    else:
      self.redirect("/signup")

class PostPage(Handler):
  
 
  def json_post(self, post_id):
    post = get_post(post_id)
    j = json.dumps(post, cls=BlogPostEncoder)
    self.response.headers["Content-Type"] = "application/json"
    self.response.write(j) 

  def get(self, post_id, format):
    if format and format=='.json':
      self.json_post(post_id)
      return
    post = get_post(post_id)
    age = time.time() - memcache.get("age"+str(post_id))
    self.render("front.html", posts = [post], age = 'Queried %d seconds ago' % age)    

class Flush(Handler):
  def get(self):
    memcache.flush_all()
    self.redirect("/")
    
class NewPost(Handler):
  def render_new(self, subject="", content="", error=""):
    self.render("new.html", subject=subject, content=content, error=error)

  def get(self):
    self.render_new()

  def post(self):
    subject = self.request.get("subject")
    content = self.request.get("content")

    if subject and content:
      p = BlogPost(subject = subject, content = content)
      p.put()
      time.sleep(0.1)
      get_front(True)
      self.redirect("/" + str(p.key().id()))
    else:
      error = "we need both a subject and a content!"
      self.render_new(subject, content, error)


application = webapp2.WSGIApplication([
  (r'/(\.json)?', MainPage),
  (r'/(\d+)(\.json)?', PostPage),
  ('/newpost', NewPost),  
  ('/signup', SignUp),
  ('/login', Login),
  ('/logout', Logout), 
	('/flush', Flush),  
  ('/welcome', Welcome),    
], debug=True)
