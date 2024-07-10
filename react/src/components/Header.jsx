import { Link } from "react-router-dom";

const Header = () => {
  return (
    <div className="mb-5">
      Header
      <Link to="/" className="btn btn-primary">Home</Link>
      <Link to="/about" className="btn btn-primary">About</Link>
      <Link to="/contact" className="btn btn-primary">Contact</Link>
      <Link to="/service" className="btn btn-primary">Service</Link>
    </div>
  );
};

export default Header;
