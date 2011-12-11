import datetime
import os
import tornado.httpclient
import tornado.ioloop
import tornado.web
import re
import sys

from optparse import OptionParser
from subprocess import Popen, PIPE, STDOUT
from tornado.web import URLSpec

parser = OptionParser()
parser.add_option("-s", "--scans_root", dest="scans_root",
    help = "Root directory containing the scans.")
parser.add_option("-b", "--scanbinary", dest="scan_binary",
    help = "Path to the scanning binary.", default="do_scan.sh")

#####################################
###     Controller classes        ###
#####################################
class ScannerController(object):
  def __init__(self, scan_binary, scans_root):
    self._scanner_binary = scan_binary
    self._root = scans_root
    self._scan_subprocess = None
    self._scan_name = ""
    self._last_rc = 0
    self._last_output = ''

  def scan_in_progress(self):
    return self._scan_subprocess != None

  def is_scan_done(self):
    p = self._scan_subprocess
    in_progress = p.poll() is None
    if not in_progress:
      self._last_rc = p.returncode
      self._last_output = p.stdout.read()
      self._scan_subprocess = None

    return not in_progress

  def last_scan_successful(self):
    return self._last_rc == 0

  def get_last_scan_results(self):
    return (self._last_rc, self._last_output)

  def start_scan(self, scan_name):
    self._scan_name = scan_name
    self._scan_subprocess = Popen(
        [self._scanner_binary, self._scan_name, self._root], 
        stdout=PIPE, stderr=STDOUT)

  def get_last_scan_name(self):
    return self._scan_name

class ScansManager(object):
  """Always returns (and exects) file name, including the jpeg suffix.
  """
  def __init__(self, root_dir):
    self._root = root_dir

  def get_jpegs_list(self):
    all_files = os.listdir(self._root) 
    return [t for t in all_files if t.endswith('.jpg')]

  def delete_scan(self, scan_name):
    fullname = os.path.join(self._root, scan_name)
    if os.path.exists(fullname):
      os.remove(fullname)

  def does_image_exist(self, scan_name):
    fullname = os.path.join(self._root, scan_name)
    return os.path.exists(fullname)


#####################################
###     Presenter classes         ###
#####################################
class MainHandler(tornado.web.RequestHandler):
  def get(self):
    self.redirect(self.reverse_url('main'), permanent=True)

class ScanListHandler(tornado.web.RequestHandler):
  def initialize(self, scans_manager):
    self._manager = scans_manager

  def get(self):
    scans_list = '<ul>'
    for scan_image in self._manager.get_jpegs_list():
      show_url = self.reverse_url('single_scan', scan_image.split('.')[0])
      scans_list += '<li><a href=%s>%s</a></li>' % (show_url, scan_image)
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
  def initialize(self, scan_controller):
    self._alphanumeric_re = re.compile('[\w]+\Z')
    self._scanner = scan_controller

  def _redirect_here(self, msg):
    self.set_header("Refresh", "2; url=" + self.reverse_url('do_scan'))
    self.write('<html><body>')
    self.write('<p>%s</p>' % msg)
    self.write('</body></html>')

  def get(self):
    if not self._scanner.scan_in_progress():
      self.send_error(404)
      return
    if self._scanner.is_scan_done():
      if not self._scanner.last_scan_successful():
        self.send_error(500)
        return
      red_url = self.reverse_url('single_scan', self._scanner.get_last_scan_name())
      self.redirect(red_url, permanent=False)
      #self.set_header("Content-Type", "text/plain")
      #self.write('Image scanned successfully: %s' % (self._scanner.get_last_scan_name()))
    else:
      # Not done yet - redirect here again.
      self._redirect_here('Still scanning...')

  def post(self):
    scan_name = self.get_argument('scan_name')
    if not self._alphanumeric_re.match(scan_name):
      self.send_error(400)
      return
    if self._scanner.scan_in_progress():
      self.send_error(503)
      return

    self._scanner.start_scan(scan_name)
    self._redirect_here('Scan initiated.')

  def write_error(self, status_code, **kwargs):
    self.write('<html><body>')
    if status_code == 400:
      self.write('<p>Not an alphanumeric name.</p>')
      self.write('<a href="/show_scans">Go back.</a>')
    elif status_code == 503:
      self.write('<p>Scanning in progress.</p>')
    elif status_code == 404:
      self.write('<p>No scan is in progress.</p>')
    elif status_code == 500 and not self._scanner.last_scan_successful():
      (last_rc, last_out) = self._scanner.get_last_scan_results()
      self.write('<p>Scan failure. Error code: %d. Output:</p>' % (last_rc))
      self.write('<p>%s</p>' % last_out)
    else:
      self.write('<p>Unknown error.</p>')
    self.write('</body></html>')

class SingleScanHandler(tornado.web.RequestHandler):
  def initialize(self, scans_manager):
    self._manager = scans_manager

  def get(self, *args, **kwargs):
    scan_name = args[0] + '.jpg'
    if not self._manager.does_image_exist(scan_name):
      self.send_error(404)
      return

    self.write('<html><body>')
    #self.write('<p><a href="%s">Back to main page.</a></p>' %
    #    self.reverse_url('main'))
    self.write(
        '<form action="%s" method="get">'
        '<input type="submit" value="Back to scans list"/>'
        '</form>' % (self.reverse_url('main')))

    del_url = self.reverse_url('single_scan', args[0])
    self.write(
        '<form action="%s" method="post">'
        '<input type="hidden" name="do_delete" value="true"/>' 
        '<input type="submit" value="Delete Scan"/>'
        '</form>' % (del_url))
    scan_img_url = self.static_url(scan_name)
    self.write('<a href="%(img)s"><img src="%(img)s" height="1024" width="768"/></a>' %
        {'img': scan_img_url})
    self.write('</body></html>')

  def post(self, *args):
    scan_name = args[0] + '.jpg'
    if not self._manager.does_image_exist(scan_name):
      self.send_error(404)
      return
    do_delete = self.get_argument('do_delete')
    if do_delete:
      self._manager.delete_scan(scan_name)
      self.redirect(self.reverse_url('main'), permanent=False)

def get_application(options):
  controller = ScannerController(options.scan_binary, options.scans_root)
  manager = ScansManager(options.scans_root)
  application = tornado.web.Application([(r"/", MainHandler),
    URLSpec(r"/show_scans", ScanListHandler, dict(scans_manager=manager), name="main"),
    URLSpec(r"/single_scan/(.*).jpg", SingleScanHandler, dict(scans_manager=manager), name="single_scan"),
    URLSpec(r"/do_scan", DoScanHandler, dict(scan_controller=controller), name="do_scan"),
    ], static_path=options.scans_root)
  return application

if __name__ == "__main__":
  (options, args) = parser.parse_args()
  if options.scans_root is None:
    print 'Missing scans root.'
    sys.exit(1)

  application = get_application(options)
  port = 8081
  application.listen(port)
  print('Application about to listen on port %d' % port)
  tornado.ioloop.IOLoop.instance().start()

