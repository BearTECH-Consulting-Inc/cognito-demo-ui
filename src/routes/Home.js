import React, { Component } from "react";
import logo from "./Logo-PHC-Colour.png";
import "./Home.css";
import { connect } from "react-redux";
import cognitoUtils from "../lib/cognitoUtils";
import request from "request";
import appConfig from "../config/app-config.json";
// import Table from "../lib/Table";
// import { JsonToTable } from "react-json-to-table";
import Grid from '@material-ui/core/Grid';

const mapStateToProps = (state) => {
  return { session: state.session };
};

class Home extends Component {
  constructor(props) {
    super(props);
    this.state = { apiStatus: "Not called" };
  }

  componentDidMount() {
    if (this.props.session.isLoggedIn) {
      const options = {
        url: `${appConfig.apiUri}/phc`,
        headers: {
          "Authorization": this.props.session.credentials.auth_header,
          "Content-Type": "application/json",
          "x-amz-date": this.props.session.credentials.amzdate,
          "x-amz-security-token": this.props.session.credentials.sessionToken
        },
      };
      this.setState({ apiStatus: "Loading...", tableData: options.tableData });
      request.get(options, (err, resp, body) => {
        let apiStatus, apiResponse;
        if (err) {
          // is API server started and reachable?
          apiStatus = "Unable to reach API";
          console.error(apiStatus + ": " + err);
        } else if (resp.statusCode !== 200) {
          // API returned an error
          apiStatus = "Error response received";
          apiResponse = body;
          console.error(apiStatus + ": " + JSON.stringify(resp));
        } else {
          apiStatus = "Successful response received.";
          apiResponse = body;
        }
        console.log(options)
        this.setState({ apiStatus, apiResponse });
      });
    }
  }

  onSignOut = (e) => {
    e.preventDefault();
    cognitoUtils.signOutCognitoSession();
  };

  render() {
    return (
      <div className="Home">
        <header className="Home-header">
          <img src={logo} className="Home-logo" alt="logo" />
          {this.props.session.isLoggedIn ? (
            <div className="Home-details">
              <div>
                <p>
                  You are logged in as user {this.props.session.user.userName} (
                  {this.props.session.user.email}).
                </p>
                <div></div>
                <p>
                  <a className="Home-link" href="/#" onClick={this.onSignOut}>
                    Sign out
                  </a>
                  .
                </p>
              </div>
            </div>
          ) : (
            <div>
              <p>You are not logged in.</p>
              <a
                className="Home-link"
                href={cognitoUtils.getCognitoSignInUri()}
              >
                Sign in
              </a>
            </div>
          )}
        </header>
        <div className="Home-body">
          {this.props.session.isLoggedIn ? (
            <div>
              <div>API status: {this.state.apiStatus}</div>
              <br/> Table 1 data
              <Grid>{(this.state.apiResponse)}</Grid>
            </div>
          ) : (
            <div></div>
          )}
        </div>
        <footer className="Home-footer">
          <div>
            {this.props.session.isLoggedIn ? (
              <div>
                <p>idToken: {this.props.session.credentials.idToken}</p>
                <p>
                  refreshToken: {this.props.session.credentials.refreshToken}
                </p>
                <p>accessToken: {this.props.session.credentials.accessToken}</p>
                <p>
                  sessionToken: {this.props.session.credentials.sessionToken}
                </p>
                <p>
                  Authorization_header:{" "}
                  {this.props.session.credentials.auth_header}
                </p>
                <p>amzdate: {this.props.session.credentials.amzdate}</p>
              </div>
            ) : (
              <div></div>
            )}
            <div className="Home-details-links"></div>
          </div>
        </footer>
      </div>
    );
  }
}

export default connect(mapStateToProps)(Home);
