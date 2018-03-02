.. oidccli documentation master file, created by
   sphinx-quickstart on Sat Dec 30 17:32:48 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to oidccli's documentation!
===================================

This is the package that implements the request-response pattern in
the OAuth2/OpenID Connect protocols.

It's the middle layer between low level oidcmsg which deals with simple messages
and their serialization and deserialization and the upper layer oidcrp which
provides the API that most service implementers should use.

.. toctree::
   :maxdepth: 2

   intro
   howto/index
   modules
   oidccli.rst
   oidccli.oauth2
   oidccli.oidc


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
