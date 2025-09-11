extern crate winres;

fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("icon.ico"); // Указываем путь к иконке
    res.compile().expect("Failed to compile Windows resources");
}
