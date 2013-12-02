# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from functools import wraps
import json
from django.http import HttpResponse

from asv_files.settings import settings as AFS
import logging
#from pytils.translit import translify #, slugify
import hashlib
import sys
import os
import re

logger = logging.getLogger(__name__)


def gen_uuid(req=None):
    from asv_files.models import UploaderSess
    if req:
        u = UploaderSess.create(req)
        uuid = u.uuid
    else:
        if AFS.ASV_FILES__DEBUG:
            logger.error('gen_uuid::only gen')
        u = UploaderSess.create()
        uuid = u.uuid
    return uuid


def may_be_json(f, *args, **kwargs):
    @wraps(f)
    def ex(req, *args, **kwargs):
        rv = f(req, *args, **kwargs)
        if type(rv) in (type(''), type(()), type([]), type({})):
            rv = json.dumps(rv, indent=4) if rv else '{}'
            resp = HttpResponse(mimetype='application/json')
            resp.write(rv)
            rv = resp
        return rv

    return ex


StringTypes = [type(str('str')), type(u'unicode')]
FNsp = re.compile(r'\s+')
FNbss = re.compile(r'^_+')
FNess = re.compile(r'_+$')
FNdsp = [
    re.compile(r'_\.'),
    re.compile(r'\._'),
    re.compile(r'-\.'),
    re.compile(r'\.-'),
]
FNdspsp = [
    re.compile(r'_-'),
    re.compile(r'-_'),
    re.compile(r'--'),
]
FNmsp = re.compile(r'_+')
#FNother=re.compile(r'[\\\(\)\'\"\@\#\$\%\^\&\*\!\/]')
FNother = re.compile(r'[^-\.\w]')
#---------------------------------------------------------------
#---------------------------------------------------------------
class Enum(object):
    def __init__(self, **kwargs):
        self._attrs = kwargs

    def __getattr__(self, name):
        if name not in self._attrs:
            raise AttributeError(name)
        return self._attrs[name]

    def __iter__(self):
        return self._attrs.iteritems()

        #---------------------------------------------------------------

#---------------------------------------------------------------
def Str2Int(a, D=0):
    '''
    Convert String to Integer if it's possible
    return D or zerro if not possible
    '''
    try:
        rv = int(a)
    except:
        rv = D
    return rv

#---------------------------------------------------------------
#---------------------------------------------------------------
def CleanFileName(filename):
    '''
    Transliting filename from russian language
    Removing double spaces, commas, dots, dashes, and some condition chars from filename
    '''
    try:
        extension = filename[filename.rindex("."):]
    except ValueError:
        extension = ""
    return hashlib.sha256("str").hexdigest()+extension


#---------------------------------------------------------------
#---------------------------------------------------------------
def get_file_hash(filename, algo='sha512', buffsize=1024 * 1024):
    rv = None
    h = hashlib.new(algo)
    with open(filename, 'rb') as fd:
        while True:
            b = fd.read(buffsize)
            if not b:
                break
            h.update(b)
    rv = h.hexdigest()
    return rv

#---------------------------------------------------------------
#---------------------------------------------------------------
def get_pname():
    pname = sys.argv[0].split(os.sep)[-1]
    pname = pname.split('.')[0]
    return pname

#---------------------------------------------------------------
#---------------------------------------------------------------
def u8(c):
    if (sys.version_info.major < 3):
        rv = c.encode('utf-8')
    else:
        rv = c
    return rv