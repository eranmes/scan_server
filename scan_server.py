import datetime
import os
import tornado.httpclient
import tornado.ioloop
import tornado.web
import re
import sys

from optparse import OptionParser
parser = OptionParser()
parser.add_option("-s", "--scans_root", dest="scans_root",
    help = "Root directory containing the scans.")

def get_jpegs_list(in_dir):
  return [t for t in os.listdir(in_dir) if t.endswith('.jpg')]

class MainHandler(tornado.web.RequestHandler):
  def get(self):
    self.redirect('/show_scans', permanent=True)

class ScanListHandler(tornado.web.RequestHandler):
  def initialize(self, scans_root):
    self._root = scans_root

  def get(self):
    scans_list = '<ul>'
    for scan_image in get_jpegs_list(self._root):
      img_url = self.static_url(scan_image)
      scans_list += '<li><a href=%s>%s</a></li>' % (img_url, scan_image)
    scans_list += '</ul>'
    self.write('<html><head><title>Scanner Web Interface.</title></head>')
    self.write('<body>'
        '<div>Existing scans: '
        '<p>' + scans_list + '</p></div>'
        '<div>Name for the next scan:</div>'
        '<form action="/do_scan" method="post">'
        '<input type="text" name="scan_name">'
        '<input type="submit" value="Submit">'
        '</form>'
        '</body>')
    self.write('</html>')

class DoScanHandler(tornado.web.RequestHandler):
  def __init__(self):
    self._alphanumeric_re = re.compile('[\w]+')

  def get(self):
    self.write('Your image goes here.')

  def post(self):
    scan_name = self.get_argument('scan_name')
    if not self._alphanumeric_re.match(scan_image):
      self.send_error()
      return

    self.set_header("Content-Type", "text/plain")
    self.write("Will scan to " + scan_name)

  def write_error(status_code, **kwargs):
    self.set_header("Content-Type", "text/plain")
    self.write("Not an alphanumeric name.")

def get_application(scans_root):
  application = tornado.web.Application([(r"/", MainHandler),
    (r"/show_scans", ScanListHandler, dict(scans_root=scans_root)),
    (r"/do_scan", DoScanHandler),
    ], static_path=scans_root)
  return application

if __name__ == "__main__":
  (options, args) = parser.parse_args()
  if options.scans_root is None:
    print 'Missing scans root.'
    sys.exit(1)

  application = get_application(options.scans_root)
  port = 8081
  application.listen(port)
  print('Application about to listen on port %d' % port)
  tornado.ioloop.IOLoop.instance().start()

