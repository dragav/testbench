#pragma once

namespace FunctionContainers
{
    typedef std::function<void()> Callback;
    typedef std::shared_ptr<Callback> CallbackSPtr;

    class FunctionContainer
    {
    public:
        FunctionContainer()
        {
            Value = 0;
        }

        FunctionContainer(int val)
        {
            Value = val;
        }

        virtual ~FunctionContainer() {}

        int Value;
    };

    typedef std::shared_ptr<FunctionContainer> FunctionContainerSPtr;

    class Item
    {
    public:
        Item()
        {
            Value = -1;
        }

        Item(int value)
        {
            Value = value;
        }

        virtual ~Item() {}

        int Value;

    };

    class FunctionContainerRepro
    {
    public:
        static void PrintArray(std::vector<Item> items);
        static bool ModifyItem(std::vector<Item>& items, int oldVal, int newVal);
        static void Repro();
    };
}