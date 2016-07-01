/*
 * Public domain
 * HMAC-SHA256 implementation
 */

#include "m_pd.h" // INTERFACE: pd interface
#include "hmacsha256.h"

// CLASS: prepare pd class
static t_class *hmacsha256_class; //hmacsha256_class is going to be a pointer to the new class.

// DATA-SPACE: define data-space for class (these are the variables of the pd object)
typedef struct hmacsha256
{
  t_object x_obj; // t_object is used to store internal object-properties like the graphical presentation of the object or data about inlets and outlets
  t_atom *ap2, *ap;
  t_int i_n1, i_n2, i_n3; // The integer variables i_n(x) stores the ??-value.
  t_int i_changed; // The integer variable i_changed stores the ??-value.
} t_hmacsha256; // The structure t_hmacsha256 (of the type _hmacsha256) is the data space of the class

// MEATHOD SPACE???
static void hmacsha256_list2(t_hmacsha256 *x, t_symbol *s, int argc, t_atom *argv) //This method has an argument of the type t_hmacsha256, which would enable us to manipulate the data space.
{
  x->i_changed = 1;
  if (x->i_n2 != argc) {
    freebytes(x->ap2, x->i_n2 * sizeof(t_atom));
    x->i_n2 = argc;
    x->ap2 = copybytes(argv, argc * sizeof(t_atom));
  } else memcpy(x->ap2, argv, argc * sizeof(t_atom));
}

static void hmacsha256_list(t_hmacsha256 *x, t_symbol *s, int argc, t_atom *argv) //This method has an argument of the type t_hmacsha256, which would enable us to manipulate the data space.
{
  if (x->i_n3 != x->i_n2+argc) {
    freebytes(x->ap, x->i_n3 * sizeof(t_atom));
    x->i_n1 = argc;
    x->i_n3  = x->i_n1+x->i_n2;
    x->ap = (t_atom *)getbytes(sizeof(t_atom)*x->i_n3);
    memcpy(x->ap+argc, x->ap2, x->i_n2*sizeof(t_atom));
  } else if ((x->i_n1 != argc)||x->i_changed)memcpy(x->ap+argc, x->ap2, x->i_n2*sizeof(t_atom));

  x->i_n1 = argc;
  memcpy(x->ap, argv, x->i_n1*sizeof(t_atom));

  x->i_changed=0;

  outlet_list(x->x_obj.ob_outlet, gensym("list"), x->i_n3, x->ap);
}

static void hmacsha256_bang(t_hmacsha256 *x) //This method has an argument of the type t_hmacsha256, which would enable us to manipulate the data space.
{
  if (x->i_changed) {
    if (x->i_n1+x->i_n2 != x->i_n3){
      t_atom *ap = (t_atom*)getbytes(sizeof(t_atom)*(x->i_n1+x->i_n2));
      memcpy(ap, x->ap, x->i_n1*sizeof(t_atom));
      freebytes(x->ap, sizeof(t_atom)*x->i_n3);
      x->ap=ap;
      x->i_n3=x->i_n1+x->i_n2;
    }
    memcpy(x->ap+x->i_n1, x->ap2, x->i_n2*sizeof(t_atom));
    x->i_changed=0;
  }

  outlet_list(x->x_obj.ob_outlet, gensym("list"), x->i_n3, x->ap);
}

static void hmacsha256_free(t_hmacsha256 *x) //This method has an argument of the type t_hmacsha256, which would enable us to manipulate the data space.
{
  freebytes(x->ap,  sizeof(t_atom)*x->i_n3);
  freebytes(x->ap2, sizeof(t_atom)*x->i_n2);
}

static void hmacsha256_help(t_hmacsha256 *x) //This method has an argument of the type t_hmacsha256, which would enable us to manipulate the data space.
{
  post("A puredata external for computing SHA256 HMACs");//The command post(char *c,...) sends a string to the standard error.
}

// CONSTRUCTOR: Each time, an object is created in a Pd-patch, the constructor that is defined with the class_new-command, generates a new instance of the class.
static void *hmacsha256_new(t_symbol *s, int argc, t_atom *argv) // The arguments of the constructor-method depend on the object-arguments defined with class_new EX. A_GIMME = t_symbol *s, int argc, t_atom *argv
{
  t_hmacsha256 *x = (t_hmacsha256 *)pd_new(hmacsha256_class); // The function pd_new reserves memory for the data space, initialises the variables that are internal to the object and returns a pointer to the data space.

  inlet_new(&x->x_obj, &x->x_obj.ob_pd, gensym("list"), gensym(""));
  outlet_new(&x->x_obj, 0); // A new outlet is created with the function outlet_new. The first argument is a pointer to the interna of the object the new outlet is created for.
  x->i_n3 =x->i_n2  = 0;
  x->ap=x->ap2 = 0;
  x->i_changed   = 0;

  if (argc)hmacsha256_list2(x, gensym("list"), argc, argv);

  return (x); //The constructor has to return a pointer to the instantiated data space.
}

// SETUP GENERATION
void hmacsha256_setup(void) //  information of the data space and the method space of this class, have to be passed to Pd when a library is loaded.
{
  hmacsha256_class = class_new(gensym("hmacsha256"), // The function class_new creates a new class and returns a pointer to this prototype.
    (t_newmethod)hmacsha256_new, // the class-constructor (t_newmethod)helloworld_new instantiates the object and initialises the data space.
    (t_method)hmacsha256_free, // Whenever an object is destroyed the destructor frees the dynamically reserved memory. The allocated memory for the static data space is automatically reserved and freed.
    sizeof(t_hmacsha256), 0, //To enable Pd to reserve and free enough memory for the static data space, the size of the data structure has to be passed as the fourth argument.
    A_GIMME, 0); // The fifth argument has influence on the graphical representation of the class objects and define the arguments of an object and its type.
  class_addlist    (hmacsha256_class, hmacsha256_list); //class_addlist adds a method for a “list”-message to the class that is defined in the first argument. The added method is defined in the second argument.
  class_addmethod  (hmacsha256_class, (t_method)hmacsha256_list2, gensym(""), A_GIMME, 0);
  class_addbang    (hmacsha256_class, hmacsha256_bang); // class_addbang adds a method for a “bang”-message to the class that is defined in the first argument. The added method is defined in the second argument.
  class_addmethod  (hmacsha256_class, (t_method)hmacsha256_help, gensym("help"), 0); // When a "help" message is sent to first inlet
}
