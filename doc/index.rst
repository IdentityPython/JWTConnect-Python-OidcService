.. oiccli documentation master file, created by
   sphinx-quickstart on Sat Dec 30 17:32:48 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to oiccli's documentation!
==================================

This is the package that implements the request-response pattern in
the OAuth2/OpenID Connect protocols.

It's the middle layer between low level oicmsg which deals with simple messages
and their serialization and deserialization and the upper layer oicrp which
provides the API that most service implementers should use.

.. toctree::
   :maxdepth: 2

   intro
   howto/index
   modules
   oiccli.rst
   oiccli.oauth2
   oiccli.oic


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
