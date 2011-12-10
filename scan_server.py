import datetime
import os
import tornado.httpclient
import tornado.ioloop
import tornado.web

import re

def get_jpegs_list(in_dir):
  return [t for t in os.listdir(in_dir) if t.endswith('.jpg')]

class MainHandler(tornado.web.RequestHandler):
  def get(self):
    self.redirect('/show_scans', permanent=True)

class ScanListHandler(tornado.web.RequestHandler):
  def get(self):
    scans_list = '<ul>'
    for scan_image in get_jpegs_list('/home/eran/scans'):
      scans_list += '<li>' + scan_image + '</li>'
    scans_list += '</ul>'
    self.write('<html><body>'
        '<div>Existing scans: '
        '<p>' + scans_list + '</p></div>'
        '<div>Name for the next scan:</div>'
        '<form action="/do_scan" method="post">'
        '<input type="text" name="scan_name">'
        '<input type="submit" value="Submit">'
        '</form>'
        '</body></html>')

class DoScanHandler(tornado.web.RequestHandler):
  def get(self):
    self.write('Your image goes here.')

  def post(self):
    scan_name = self.get_argument('scan_name')

    self.set_header("Content-Type", "text/plain")
    self.write("Will scan to " + scan_name)

def get_application():
  application = tornado.web.Application([(r"/", MainHandler),
    (r"/show_scans", ScanListHandler),
    (r"/do_scan", DoScanHandler),
    ])
  return application

if __name__ == "__main__":
  application = get_application()
  port = 8081
  application.listen(port)
  print('Application about to listen on port %d' % port)
  tornado.ioloop.IOLoop.instance().start()

