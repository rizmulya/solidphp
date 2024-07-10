import { useLocation } from "react-router-dom"

const NotFound = () => {
  const location = useLocation();
  const fullUrl = `${window.location.origin}${location.pathname}${location.search}${location.hash}`;
  return (
    <div>NotFound: {fullUrl}</div>
  )
}

export default NotFound