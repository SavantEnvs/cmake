/* header comment */
// line comment
package a.b.c; // trailing
/** doc */
public final class C {
  /* inner */ native void f(); // native
  synchronized void g() throws Exception { try { f(); } catch (Exception e) { throw e; } finally { } }
}
