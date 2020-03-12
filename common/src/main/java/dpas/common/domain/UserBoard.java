package dpas.common.domain;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullPostException;
import dpas.common.domain.exception.NullUserException;

import java.util.ArrayList;

public class UserBoard implements AnnouncementBoard {
    public ArrayList<Post> posts;
    public User owner;

    @Override
    public void post(User user, Post post) throws NullPostException, NullUserException, InvalidUserException {
        checkArguments(user, post);
        posts.add(post);
    }

    public void checkArguments(User user, Post post) throws NullUserException, NullPostException, InvalidUserException {
        if (user == null) {
            throw new NullUserException();
        }
        if (post == null) {
            throw new NullPostException();
        }
        if (user == owner) {
            throw new InvalidUserException();
        }
    }

    @Override
    public Post[] read(int number) throws InvalidNumberOfPostsException {
        if (number <= 0 || number > posts.size())
            throw new InvalidNumberOfPostsException();
        return (Post[]) posts.subList(posts.size()-number, posts.size()).toArray();
    }
}
