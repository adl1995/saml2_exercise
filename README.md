# GÉANT T&I Devops Engineer Assessment

## Introduction

This repository contains a trivial Flask
application that serves "Hello, World" on "/"

## Running the Current State of the Web Service

* Ensure you have a relatively recent version
  of Python 3.x installed on your system

* Create and enter a Python virtual environment.  For example:

```bash
$ git clone https://github.com/erik-geant/saml2_exercise.git
$ cd saml2_exercise
# can be any reasonable python 3.x version
$ python3.10 -m venv venv
$ . venv/bin/activate
(venv) $ pip install -e .
```

* Run the Web Service

```bash
(venv) $ python -m saml2_exercise.server
```

* Verify the Web Service is Serving on 8989

```bash
# in another shell:
$ curl http://localhost:8989/
```

## Assignment
Federate the web service as a SAML 2.0 Service Provider.

Our IDP metatdata can be found here:

  * https://test-idp-o365.geant.org/saml2/idp/metadata.php


**Be sure to ask for any support needed
(for example, server-side configuration changes)
to enable authentication of your Service Provider
using our IDP.**

In the end, you should be able to
demonstrate that a user is required to
successfully authenticate against our IDP
in order to access the "/" resource.

