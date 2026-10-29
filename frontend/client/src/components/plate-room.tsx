import { useEffect } from "react";
import { useLocation } from "wouter";

const HOUSING = /^\/(dashboard|marketplace|profile|analysis)(\/|$)/;

/** Bench for the public site. Housing for the console. The route decides. */
export function PlateRoom() {
  const [location] = useLocation();

  useEffect(() => {
    const housing = HOUSING.test(location);
    const root = document.documentElement;
    root.dataset.plate = housing ? "housing" : "bench";
    root.classList.toggle("dark", housing);
    root.style.colorScheme = housing ? "dark" : "light";
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", housing ? "#141513" : "#C8C5BC");
  }, [location]);

  return null;
}
