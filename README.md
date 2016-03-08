# How to use this test environment

The testing environment consists of several components:

- A test library and proxy, which intercepts and modifies requests to
  the card, to allow testing with different cards and/or features.
- A test PKI infrastructure, to create custom certificates
  for use within the test environment.
- A "fromcard" tool, used to generate a CSR (Certificate Signing
  Request) for a key on an eID card. This can then be used with the
  above test PKI infrastructure and test library to generate
  certificates valid for the given card, but containing different
  metadata or signing algorithms than the one on the card.

This repository contains the fromcard tool and the source for the PKI
infrastructure.

## Using fromcard

The fromcard tool is provided as a source file that must be modified and
compiled:

- Edit fromcard.c, and modify the #define lines at the start so that it
  contains the data of the card as you wish to see it in the test
  environment.
- Compile fromcard.c, cencode.c, and base64.h against the eID middleware
  into a program.
- Run the fromcard program which was compiled in the previous step on a
  system with a single eID card in a reader.
- Fromcard will cause the eID middleware to ask for your PIN code, and
  will then generate a CSR for the Signature and the Authentication
  keys, in that order, with the metadata as specified at the top of
  fromcard.c. **Note**: fromcard assumes that the dialogs were not
  disabled when compiling the middleware (i.e., as in the official
  distribution). If that is wrong, you may need to modify fromcard.c to
  take a PIN code from somewhere.
- Copy and paste the two CSRs into the PKI infrastructure (see below)

## Using the PKI infrastructure

The PKI infrastructure is just a shell script that runs openssl in the
right ways so that it produces a CA infrastructure with OCSP responder
that is as similar as possible to the official PKI.

It is possible to run the shell script directly on a Debian system;
however, to keep matters easy, a Docker container is available at [the
docker hub](https://hub.docker.com/f/fedict/eid-test-ca). To get
started, first install docker for your operating system. Then, do the
following:

    docker pull fedict/eid-test-ca
    docker run --name eid_test_store -v /var/lib/eid -ti fedict/eid-test-ca buildroot
    docker run --volumes-from=eid_test_store -ti fedict/eid-test-ca buildca
    docker run --volumes-from=eid_test_store -ti fedict/eid-test-ca signkey

The last command will wait for a CSR on standard input. Paste one of the
two certificates into its standard input, followed by EOF (ctrl+d). It
will output a decoded version of the CSR (for verification purposes),
and will then produce a CA-signed certificate. Take this into the test
library tool. Repeat this step for the other certificate, if necessary.

Next, run the OCSP responder:

    docker run --volumes-from=eid_test_store -ti -p 80:80 -p 8888:8888 fedict/eid-test-ca

This will run a webserver on port 80 (serving the certificates and
CRLs), and the OCSP responder on port 8888.

To revoke a certificate, run the revoke command:

    docker run --volumes-from=eid_test_store -ti fedict/eid-test-ca revoke <serial>

replacing &lt;serial&gt; by the serial number of the certificate (that
is, the certificate serial number as assigned by the CA, *not* the RRN
number)