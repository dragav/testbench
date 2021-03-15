#pragma once

namespace SpecializedDtor
{
    class X509Obj
    {
    public:
        X509Obj() 
        { 
            std::cout << "X509Obj ctor" << "\n";
            strptr = nullptr;
            strptr = (char*)init(20);
            _itoa_s(rand(), strptr, 20, 10);
            std::cout << strptr << "\n";
        }

        virtual ~X509Obj() 
        { 
            std::cout << "X509Obj dtor " << strptr << "\n";
            if (strptr) release(strptr);
            strptr = nullptr;
        }

    private:
        void* init(size_t size) { return malloc(size); }
        void release(void* buf) { free(buf); }

        char* strptr;
    };

    static X509Obj* X509_new(void) { return new X509Obj(); }
    static void X509_free(X509Obj* obj) { delete obj; }

    template <typename T>
    class ObjContext
    {
    public:
        ObjContext(T* obj = nullptr) : obj_(obj)
        {
            std::cout << "ObjContext ctor: obj_ = " << obj_ << "\n";
        }

        ObjContext(ObjContext&& other) : obj_(other.obj_), deleter_(other.deleter_)
        {
            std::cout << "ObjContext copy ctor: obj_ = " << obj_ << "\n";
            other.obj_ = nullptr;
        }

        virtual ~ObjContext()
        {
            reset();
            std::cout << "ObjContext dtor" << "\n";
        }

        ObjContext& operator=(ObjContext&& other)
        {
            if (this == &other) return *this;

            reset();

            obj_ = other.obj_;
            other.obj_ = nullptr;

            deleter_ = other.deleter_;
            other.deleter_ = nullptr;

            return *this;
        }

        operator bool() const { return obj_ != nullptr; }

        T* operator->() { return obj_; }
        T const* operator->() const { return obj_; }

        T* get() const { return obj_; }

        void reset()
        {
            std::cout << "ObjContext reset" << "\n";
            if (!obj_) return;

            deleter_(obj_);
            obj_ = nullptr;
        }

    protected:
        T* obj_ = nullptr;
        void (*deleter_)(T*) = nullptr;
    };

    class X509ContextNoDtor : public ObjContext<X509Obj>
    {
    public:
        X509ContextNoDtor(X509Obj* obj = nullptr) : ObjContext(obj)
        {
            deleter_ = X509_free;
        }
    };

    class X509ContextYesDtor : public ObjContext<X509Obj>
    {
    public:
        X509ContextYesDtor(X509Obj* obj = nullptr) : ObjContext(obj)
        {
            deleter_ = X509_free;
        }

        virtual ~X509ContextYesDtor() { reset(); }

    protected:
        virtual void reset()
        {
            std::cout << "X509ContextYesDtor reset" << "\n";
            if (!obj_) return;

            deleter_(obj_);
            obj_ = nullptr;
        }
    };

    class SpecializedDtorTest
    {
    public:
        static void Repro()
        {
            {
                std::cout << "entering scope" << "\n";
                X509ContextNoDtor aCtx(X509_new());
                std::cout << "a" << "\n";
                X509ContextYesDtor bCtx(X509_new());
                std::cout << "b" << "\n";
                std::cout << "exiting scope" << "\n";
            }
            std::cout << "outer scope exit" << "\n";
        }
    };
}
