import Header from "../components/Header";
import { Outlet } from "react-router-dom";

const AnotherLayout = () => {
  return (
    <>
      layout: AnotherLayout
      <Header />
      <Outlet />
    </>
  );
};

export default AnotherLayout;
