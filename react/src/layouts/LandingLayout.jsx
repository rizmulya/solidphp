import Header from "../components/Header";
import { Outlet } from "react-router-dom";

const LandingLayout = () => {
  return (
    <>
      layout: LandingLayout
      <Header />
      <Outlet />
    </>
  );
};

export default LandingLayout;
