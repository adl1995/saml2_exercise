# from flask import Flask
import flask
import flask_principal
import flask_saml

APP_PORT = 8989

app = flask.Flask('saml2-exercise')
principals = flask_principal.Principal(app)
app.config.update({
    'SECRET_KEY': '7fed2c81fdeb4972ab4ce72a42cec378',
    'SAML_METADATA_URL': 'https://test-idp-o365.geant.org/saml2/idp/metadata.php',
})
saml = flask_saml.FlaskSAML(app)

# Create an admin role which is required to access the application.
admin_permission = flask_principal.Permission(flask_principal.RoleNeed('admin'))
@flask_saml.saml_authenticated.connect_via(app)
def saml_auth(sender, subject, attributes, auth):
    # We have a logged-in user, inform Flask-Principal
    flask_principal.identity_changed.send(
        flask.current_app._get_current_object(),
        identity=get_identity(),
    )

@principals.identity_loader
def get_identity():
    if 'saml' in flask.session:
        return flask_principal.Identity(flask.session['saml']['subject'])
    else:
        return flask_principal.AnonymousIdentity()


@flask_principal.identity_loaded.connect_via(app)
def handle_identity(sender, identity):
    if not isinstance(identity, flask_principal.AnonymousIdentity):
        # Give user admin role if they successfully authenticate.
        identity.provides.add(flask_principal.RoleNeed('admin'))


@app.route('/')
@admin_permission.require()
def default_route():
    return '<h1>Hello, World!</h1>'


@app.errorhandler(flask_principal.PermissionDenied)
def handle_permission_denied(error):
    deny_message = 'Permission Denied', 403
    redirect = flask.redirect(flask.url_for('login', next=flask.request.url))
    if isinstance(flask.g.identity, flask_principal.AnonymousIdentity):
        return redirect
    else:
        return deny_message


if __name__ == "__main__":
    app.run(host='::', port=str(APP_PORT))
