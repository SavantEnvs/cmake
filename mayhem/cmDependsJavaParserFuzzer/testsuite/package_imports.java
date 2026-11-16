package org.example.app;

import java.util.List;
import java.util.Map;
import static java.lang.Math.max;
import org.example.util.*;

public class Outer extends Base implements Runnable, Comparable<Outer>
{
  private static final int LIMIT = 10;
  private Helper helper = new Helper();

  public static class Nested
  {
    void go() { Other o = new Other(); o.run(); }
  }

  interface Callback { void done(int status); }

  @Override
  public void run()
  {
    for (int i = 0; i < LIMIT; ++i) {
      helper.step(i);
    }
  }

  public int compareTo(Outer other) { return 0; }
}
