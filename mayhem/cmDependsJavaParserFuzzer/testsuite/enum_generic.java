package p;

enum Color { RED, GREEN, BLUE }

abstract class Box<T extends Number>
{
  protected T value;
  abstract T get();
  static <U> U first(java.util.List<U> l) { return l.get(0); }
  int[] arr = new int[] { 1, 2, 3 };
  String s = "a \"quoted\" string" + 'c';
}
